#!/usr/bin/env python3
"""macOS per-process network usage logger and local dashboard.

The collector samples Apple's `nettop` in per-process delta mode, stores every
sample and process delta in SQLite, and serves a local dashboard for daily
network-traffic analysis.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sqlite3
import subprocess
import sys
import threading
import urllib.parse
from dataclasses import asdict, dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable, cast

APP_NAME = "NetworkTrafficDashboard"
DEFAULT_BIND = "127.0.0.1:18686"
DEFAULT_INTERVAL_SECONDS = 60
SCHEMA_VERSION = 2
DATABASE_FILENAME = "network_traffic.sqlite3"


def default_data_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    return Path.home() / f".{APP_NAME.lower()}"


@dataclass(frozen=True)
class ProcessDelta:
    raw_process: str
    process: str
    pid: int | None
    bytes_in: int
    bytes_out: int

    @property
    def total_bytes(self) -> int:
        return self.bytes_in + self.bytes_out

    def to_log_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["total_bytes"] = self.total_bytes
        data["is_tunnel"] = is_tunnel_process(self.process)
        return data


class CollectorState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.last_sample_at: str | None = None
        self.last_error: str | None = None
        self.last_process_count = 0
        self.last_total_bytes = 0
        self.samples_written = 0

    def record_sample(self, timestamp: datetime, rows: list[ProcessDelta]) -> None:
        with self._lock:
            self.last_sample_at = timestamp.isoformat(timespec="seconds")
            self.last_error = None
            self.last_process_count = len(rows)
            self.last_total_bytes = sum(row.total_bytes for row in rows)
            self.samples_written += 1

    def record_error(self, error: str) -> None:
        with self._lock:
            self.last_error = error

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "last_sample_at": self.last_sample_at,
                "last_error": self.last_error,
                "last_process_count": self.last_process_count,
                "last_total_bytes": self.last_total_bytes,
                "samples_written": self.samples_written,
            }


def is_tunnel_process(process: str) -> bool:
    lowered = process.lower()
    return any(token in lowered for token in ("macpackettunnel", "shadowrocket", "packet tunnel"))


def parse_process_identity(raw_process: str) -> tuple[str, int | None]:
    """Split nettop's `Process Name.pid` value without breaking dotted names."""
    name, sep, suffix = raw_process.rpartition(".")
    if sep and suffix.isdigit():
        return name, int(suffix)
    return raw_process, None


def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_nettop_csv(text: str, *, skip_first_sample: bool = True) -> list[ProcessDelta]:
    """Parse CSV output from `nettop -P -x -d -L N -n`.

    nettop emits one header per sample. In delta mode the first sample can still
    contain cumulative process counters, so the collector uses `-L 2` and skips
    the first sample by default.
    """
    rows: list[ProcessDelta] = []
    sample_index = -1
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        if row[0] == "time":
            sample_index += 1
            continue
        if sample_index < 0:
            continue
        if skip_first_sample and sample_index == 0:
            continue
        if len(row) < 6:
            continue

        raw_process = row[1].strip()
        if not raw_process:
            continue
        bytes_in = parse_int(row[4])
        bytes_out = parse_int(row[5])
        if bytes_in + bytes_out <= 0:
            continue

        process, pid = parse_process_identity(raw_process)
        rows.append(
            ProcessDelta(
                raw_process=raw_process,
                process=process,
                pid=pid,
                bytes_in=bytes_in,
                bytes_out=bytes_out,
            )
        )
    return rows


def collect_once(interval_seconds: int, *, nettop_path: str = "nettop") -> list[ProcessDelta]:
    if interval_seconds < 1:
        raise ValueError("interval_seconds must be >= 1")
    command = [
        nettop_path,
        "-P",
        "-x",
        "-d",
        "-L",
        "2",
        "-s",
        str(interval_seconds),
        "-n",
    ]
    timeout = max(15, interval_seconds + 10)
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or f"nettop exited with {completed.returncode}"
        raise RuntimeError(message)
    return parse_nettop_csv(completed.stdout, skip_first_sample=True)


def ensure_data_dirs(data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)


def database_path(data_dir: Path) -> Path:
    return data_dir / DATABASE_FILENAME


def local_now() -> datetime:
    return datetime.now().astimezone()


def day_string(timestamp: datetime | None = None) -> str:
    stamp = timestamp or local_now()
    if stamp.tzinfo is None:
        stamp = stamp.astimezone()
    return stamp.astimezone().date().isoformat()


def connect_database(data_dir: Path) -> sqlite3.Connection:
    ensure_data_dirs(data_dir)
    conn = sqlite3.connect(database_path(data_dir))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_database(data_dir: Path) -> Path:
    with connect_database(data_dir) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                date TEXT NOT NULL,
                source TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL,
                bytes_in INTEGER NOT NULL,
                bytes_out INTEGER NOT NULL,
                process_count INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS process_deltas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id INTEGER NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
                raw_process TEXT NOT NULL,
                process TEXT NOT NULL,
                pid INTEGER,
                bytes_in INTEGER NOT NULL,
                bytes_out INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL,
                is_tunnel INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                date TEXT NOT NULL,
                error TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_samples_date ON samples(date);
            CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
            CREATE INDEX IF NOT EXISTS idx_process_deltas_sample ON process_deltas(sample_id);
            CREATE INDEX IF NOT EXISTS idx_process_deltas_process ON process_deltas(process);
            CREATE INDEX IF NOT EXISTS idx_errors_date ON errors(date);
            """
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
    return database_path(data_dir)


def append_sample_record(
    data_dir: Path,
    rows: list[ProcessDelta],
    *,
    interval_seconds: int,
    timestamp: datetime | None = None,
    source: str = "nettop",
) -> Path:
    stamp = timestamp or local_now()
    sample_date = day_string(stamp)
    bytes_in = sum(row.bytes_in for row in rows)
    bytes_out = sum(row.bytes_out for row in rows)
    total_bytes = bytes_in + bytes_out
    init_database(data_dir)
    with connect_database(data_dir) as conn:
        cursor = conn.execute(
            """
            INSERT INTO samples(ts, date, source, interval_seconds, total_bytes, bytes_in, bytes_out, process_count)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stamp.isoformat(timespec="seconds"),
                sample_date,
                source,
                interval_seconds,
                total_bytes,
                bytes_in,
                bytes_out,
                len(rows),
            ),
        )
        sample_id = int(cursor.lastrowid)
        conn.executemany(
            """
            INSERT INTO process_deltas(sample_id, raw_process, process, pid, bytes_in, bytes_out, total_bytes, is_tunnel)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    sample_id,
                    row.raw_process,
                    row.process,
                    row.pid,
                    row.bytes_in,
                    row.bytes_out,
                    row.total_bytes,
                    1 if is_tunnel_process(row.process) else 0,
                )
                for row in rows
            ],
        )
    return database_path(data_dir)


def append_error_record(data_dir: Path, error: str, *, timestamp: datetime | None = None) -> Path:
    stamp = timestamp or local_now()
    init_database(data_dir)
    with connect_database(data_dir) as conn:
        conn.execute(
            "INSERT INTO errors(ts, date, error) VALUES(?, ?, ?)",
            (stamp.isoformat(timespec="seconds"), day_string(stamp), error),
        )
    return database_path(data_dir)


def parse_pids(value: str | None) -> list[int]:
    if not value:
        return []
    pids: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if part.isdigit():
            pids.add(int(part))
    return sorted(pids)


def empty_summary(data_dir: Path, date: str) -> dict[str, Any]:
    return {
        "date": date,
        "exists": database_path(data_dir).exists(),
        "database_path": str(database_path(data_dir)),
        "sample_count": 0,
        "error_count": 0,
        "first_sample_at": None,
        "last_sample_at": None,
        "last_error": None,
        "bytes_in": 0,
        "bytes_out": 0,
        "total_bytes": 0,
        "processes": [],
        "latest_processes": [],
    }


def summarize_day(data_dir: Path, date: str | None = None, *, top_limit: int | None = None) -> dict[str, Any]:
    selected_date = date or day_string()
    init_database(data_dir)
    with connect_database(data_dir) as conn:
        sample_stats = conn.execute(
            """
            SELECT COUNT(*) AS sample_count,
                   MIN(ts) AS first_sample_at,
                   MAX(ts) AS last_sample_at,
                   COALESCE(SUM(bytes_in), 0) AS bytes_in,
                   COALESCE(SUM(bytes_out), 0) AS bytes_out,
                   COALESCE(SUM(total_bytes), 0) AS total_bytes
            FROM samples
            WHERE date = ?
            """,
            (selected_date,),
        ).fetchone()
        error_stats = conn.execute(
            """
            SELECT COUNT(*) AS error_count, MAX(error) AS last_error
            FROM errors
            WHERE date = ?
            """,
            (selected_date,),
        ).fetchone()

        if not sample_stats or int(sample_stats["sample_count"] or 0) == 0:
            summary = empty_summary(data_dir, selected_date)
            summary["error_count"] = int(error_stats["error_count"] or 0) if error_stats else 0
            summary["last_error"] = error_stats["last_error"] if error_stats else None
            return summary

        process_query = """
            SELECT d.process AS process,
                   COALESCE(SUM(d.bytes_in), 0) AS bytes_in,
                   COALESCE(SUM(d.bytes_out), 0) AS bytes_out,
                   COALESCE(SUM(d.total_bytes), 0) AS total_bytes,
                   COUNT(*) AS samples,
                   MAX(d.is_tunnel) AS is_tunnel,
                   GROUP_CONCAT(DISTINCT d.pid) AS pids
            FROM process_deltas d
            JOIN samples s ON s.id = d.sample_id
            WHERE s.date = ?
            GROUP BY d.process
            ORDER BY total_bytes DESC
        """
        params: list[Any] = [selected_date]
        if top_limit is not None:
            process_query += " LIMIT ?"
            params.append(top_limit)
        process_rows = [dict(row) for row in conn.execute(process_query, params)]
        for row in process_rows:
            row["pids"] = parse_pids(row.get("pids"))
            row["is_tunnel"] = bool(row.get("is_tunnel"))

        latest_sample = conn.execute(
            "SELECT id FROM samples WHERE date = ? ORDER BY ts DESC, id DESC LIMIT 1",
            (selected_date,),
        ).fetchone()
        latest_rows: list[dict[str, Any]] = []
        if latest_sample:
            latest_rows = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT raw_process, process, pid, bytes_in, bytes_out, total_bytes, is_tunnel
                    FROM process_deltas
                    WHERE sample_id = ?
                    ORDER BY total_bytes DESC
                    LIMIT 20
                    """,
                    (latest_sample["id"],),
                )
            ]
            for row in latest_rows:
                row["is_tunnel"] = bool(row.get("is_tunnel"))

    return {
        "date": selected_date,
        "exists": True,
        "database_path": str(database_path(data_dir)),
        "sample_count": int(sample_stats["sample_count"] or 0),
        "error_count": int(error_stats["error_count"] or 0) if error_stats else 0,
        "first_sample_at": sample_stats["first_sample_at"],
        "last_sample_at": sample_stats["last_sample_at"],
        "last_error": error_stats["last_error"] if error_stats else None,
        "bytes_in": int(sample_stats["bytes_in"] or 0),
        "bytes_out": int(sample_stats["bytes_out"] or 0),
        "total_bytes": int(sample_stats["total_bytes"] or 0),
        "processes": process_rows,
        "latest_processes": latest_rows,
    }


def list_days(data_dir: Path) -> list[dict[str, Any]]:
    init_database(data_dir)
    with connect_database(data_dir) as conn:
        day_map: dict[str, dict[str, Any]] = {}
        for row in conn.execute(
            """
            SELECT date,
                   COUNT(*) AS sample_count,
                   COALESCE(SUM(bytes_in), 0) AS bytes_in,
                   COALESCE(SUM(bytes_out), 0) AS bytes_out,
                   COALESCE(SUM(total_bytes), 0) AS total_bytes,
                   MAX(ts) AS last_sample_at
            FROM samples
            GROUP BY date
            """
        ):
            day_map[row["date"]] = {
                "date": row["date"],
                "database_path": str(database_path(data_dir)),
                "sample_count": int(row["sample_count"] or 0),
                "error_count": 0,
                "total_bytes": int(row["total_bytes"] or 0),
                "bytes_in": int(row["bytes_in"] or 0),
                "bytes_out": int(row["bytes_out"] or 0),
                "last_sample_at": row["last_sample_at"],
            }
        for row in conn.execute("SELECT date, COUNT(*) AS error_count FROM errors GROUP BY date"):
            entry = day_map.setdefault(
                row["date"],
                {
                    "date": row["date"],
                    "database_path": str(database_path(data_dir)),
                    "sample_count": 0,
                    "error_count": 0,
                    "total_bytes": 0,
                    "bytes_in": 0,
                    "bytes_out": 0,
                    "last_sample_at": None,
                },
            )
            entry["error_count"] = int(row["error_count"] or 0)
    return sorted(day_map.values(), key=lambda item: item["date"], reverse=True)


def timeseries_day(data_dir: Path, date: str | None = None) -> list[dict[str, Any]]:
    selected_date = date or day_string()
    init_database(data_dir)
    with connect_database(data_dir) as conn:
        rows = [
            dict(row)
            for row in conn.execute(
                """
                SELECT substr(ts, 12, 2) AS hour,
                       COALESCE(SUM(bytes_in), 0) AS bytes_in,
                       COALESCE(SUM(bytes_out), 0) AS bytes_out,
                       COALESCE(SUM(total_bytes), 0) AS total_bytes,
                       COUNT(*) AS sample_count
                FROM samples
                WHERE date = ?
                GROUP BY hour
                ORDER BY hour ASC
                """,
                (selected_date,),
            )
        ]
    for row in rows:
        row["label"] = f"{row['hour']}:00"
        row["bytes_in"] = int(row["bytes_in"] or 0)
        row["bytes_out"] = int(row["bytes_out"] or 0)
        row["total_bytes"] = int(row["total_bytes"] or 0)
        row["sample_count"] = int(row["sample_count"] or 0)
    return rows


def human_bytes(value: int | float) -> str:
    number = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(number) < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(number)} {unit}"
            return f"{number:.1f} {unit}"
        number /= 1024
    return f"{number:.1f} TB"


def print_report(summary: dict[str, Any], *, top: int) -> None:
    print(f"Date: {summary['date']}")
    print(f"Database: {summary['database_path']}")
    print(
        "Total: "
        f"{human_bytes(summary['total_bytes'])} "
        f"(in {human_bytes(summary['bytes_in'])}, out {human_bytes(summary['bytes_out'])})"
    )
    print(f"Samples: {summary['sample_count']}  Errors: {summary['error_count']}")
    print("")
    print(f"{'process':32s} {'total':>12s} {'in':>12s} {'out':>12s}  pids")
    print("-" * 82)
    for row in summary["processes"][:top]:
        pids = ",".join(str(pid) for pid in row.get("pids", [])[:6])
        suffix = "  [tunnel]" if row.get("is_tunnel") else ""
        print(
            f"{row['process'][:32]:32s} "
            f"{human_bytes(row['total_bytes']):>12s} "
            f"{human_bytes(row['bytes_in']):>12s} "
            f"{human_bytes(row['bytes_out']):>12s}  "
            f"{pids}{suffix}"
        )


DASHBOARD_HTML = """<!doctype html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Network Traffic Dashboard</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0b1020; color: #e7edf7; }
    header { padding: 22px 28px; background: linear-gradient(135deg, #141b34, #0f172a); border-bottom: 1px solid #26324f; }
    h1 { margin: 0 0 8px; font-size: 25px; }
    .muted { color: #97a5c0; }
    main { padding: 24px; max-width: 1240px; margin: 0 auto; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; margin-bottom: 18px; }
    .card { background: #11182c; border: 1px solid #25304a; border-radius: 14px; padding: 16px; box-shadow: 0 12px 28px rgba(0, 0, 0, 0.22); }
    .card .label { color: #9fb0d0; font-size: 13px; }
    .card .value { font-size: 25px; margin-top: 8px; font-weight: 700; }
    .toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin: 14px 0 18px; }
    select, button, a.button { background: #18233d; color: #e7edf7; border: 1px solid #34425f; border-radius: 10px; padding: 9px 12px; text-decoration: none; }
    button:hover, a.button:hover { background: #22304f; cursor: pointer; }
    .charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); gap: 14px; margin: 18px 0; }
    .chart-card { background: #11182c; border: 1px solid #25304a; border-radius: 14px; padding: 16px; }
    .chart-title { margin: 0 0 10px; color: #c7d2fe; font-size: 14px; }
    canvas { width: 100%; height: 250px; display: block; }
    table { width: 100%; border-collapse: collapse; background: #11182c; border: 1px solid #25304a; border-radius: 14px; overflow: hidden; }
    th, td { padding: 11px 12px; border-bottom: 1px solid #202a42; text-align: left; }
    th { background: #151f38; color: #aebddb; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
    tr:last-child td { border-bottom: none; }
    .bar { height: 7px; background: #24304c; border-radius: 999px; overflow: hidden; min-width: 90px; }
    .bar span { display: block; height: 100%; background: linear-gradient(90deg, #38bdf8, #22c55e); }
    .pill { display: inline-block; padding: 3px 8px; border-radius: 999px; font-size: 12px; background: #334155; color: #dbeafe; margin-left: 6px; }
    .error { color: #f87171; }
    footer { margin-top: 18px; color: #8492ad; font-size: 13px; }
  </style>
</head>
<body>
  <header>
    <h1>Network Traffic Dashboard</h1>
    <div class="muted">Per-process macOS traffic from nettop. MacPacketTunnel and Shadowrocket rows are aggregate tunnel usage.</div>
  </header>
  <main>
    <div class="toolbar">
      <label>Day: <select id="daySelect"></select></label>
      <button id="refreshBtn">Refresh</button>
      <a id="csvLink" class="button" href="#">CSV export</a>
      <span id="status" class="muted"></span>
    </div>
    <section class="cards">
      <div class="card"><div class="label">Selected-day total</div><div id="total" class="value">-</div></div>
      <div class="card"><div class="label">Download</div><div id="bytesIn" class="value">-</div></div>
      <div class="card"><div class="label">Upload</div><div id="bytesOut" class="value">-</div></div>
      <div class="card"><div class="label">Samples</div><div id="samples" class="value">-</div></div>
    </section>
    <section class="charts">
      <div class="chart-card"><h2 class="chart-title">Daily totals</h2><canvas id="dailyChart"></canvas></div>
      <div class="chart-card"><h2 class="chart-title">Hourly traffic for selected day</h2><canvas id="hourlyChart"></canvas></div>
      <div class="chart-card"><h2 class="chart-title">Top processes for selected day</h2><canvas id="processChart"></canvas></div>
    </section>
    <table>
      <thead><tr><th>Process</th><th>Total</th><th>Download</th><th>Upload</th><th>Share</th><th>PIDs</th></tr></thead>
      <tbody id="rows"><tr><td colspan="6">Loading...</td></tr></tbody>
    </table>
    <footer id="footer"></footer>
  </main>
<script>
const fmtBytes = (value) => {
  let n = Number(value || 0);
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  for (const unit of units) {
    if (Math.abs(n) < 1024 || unit === 'TB') return unit === 'B' ? `${Math.round(n)} ${unit}` : `${n.toFixed(1)} ${unit}`;
    n /= 1024;
  }
};
const escapeHtml = (s) => String(s).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
function prepareCanvas(canvas) {
  const ratio = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.max(1, Math.floor(rect.width * ratio));
  canvas.height = Math.max(1, Math.floor(rect.height * ratio));
  const ctx = canvas.getContext('2d');
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  return { ctx, width: rect.width, height: rect.height };
}
function drawBars(canvas, items, options = {}) {
  const { ctx, width, height } = prepareCanvas(canvas);
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = '#97a5c0';
  ctx.font = '12px -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  if (!items.length) {
    ctx.fillText('No data yet', 14, 28);
    return;
  }
  const labelKey = options.labelKey || 'label';
  const valueKey = options.valueKey || 'total_bytes';
  const color = options.color || '#38bdf8';
  const max = Math.max(...items.map(item => Number(item[valueKey] || 0)), 1);
  const padLeft = options.horizontal ? 112 : 34;
  const padBottom = 34;
  const padTop = 18;
  const chartW = width - padLeft - 12;
  const chartH = height - padTop - padBottom;
  ctx.strokeStyle = '#26324f';
  ctx.beginPath();
  ctx.moveTo(padLeft, padTop);
  ctx.lineTo(padLeft, padTop + chartH);
  ctx.lineTo(width - 10, padTop + chartH);
  ctx.stroke();
  if (options.horizontal) {
    const gap = 7;
    const barH = Math.max(10, (chartH - gap * (items.length - 1)) / items.length);
    items.forEach((item, idx) => {
      const y = padTop + idx * (barH + gap);
      const value = Number(item[valueKey] || 0);
      const barW = Math.max(1, (value / max) * chartW);
      ctx.fillStyle = '#9fb0d0';
      ctx.fillText(String(item[labelKey]).slice(0, 16), 8, y + barH * 0.75);
      ctx.fillStyle = color;
      ctx.fillRect(padLeft, y, barW, barH);
      ctx.fillStyle = '#e7edf7';
      ctx.fillText(fmtBytes(value), Math.min(padLeft + barW + 6, width - 76), y + barH * 0.75);
    });
    return;
  }
  const gap = 8;
  const barW = Math.max(8, (chartW - gap * (items.length - 1)) / items.length);
  items.forEach((item, idx) => {
    const value = Number(item[valueKey] || 0);
    const barH = (value / max) * chartH;
    const x = padLeft + idx * (barW + gap);
    const y = padTop + chartH - barH;
    ctx.fillStyle = color;
    ctx.fillRect(x, y, barW, barH);
    ctx.save();
    ctx.translate(x + Math.min(18, barW), padTop + chartH + 18);
    ctx.rotate(-Math.PI / 5);
    ctx.fillStyle = '#9fb0d0';
    ctx.fillText(String(item[labelKey]).slice(0, 11), 0, 0);
    ctx.restore();
  });
  ctx.fillStyle = '#e7edf7';
  ctx.fillText(fmtBytes(max), padLeft + 6, padTop + 12);
}
async function loadDays() {
  const days = await fetch('/api/days').then(r => r.json());
  const select = document.getElementById('daySelect');
  const previous = select.value;
  select.innerHTML = '';
  if (!days.days.length) {
    const opt = document.createElement('option'); opt.value = ''; opt.textContent = 'today'; select.appendChild(opt);
    drawBars(document.getElementById('dailyChart'), []);
    return;
  }
  for (const day of days.days) {
    const opt = document.createElement('option');
    opt.value = day.date;
    opt.textContent = `${day.date} - ${fmtBytes(day.total_bytes)}`;
    select.appendChild(opt);
  }
  if (previous) select.value = previous;
  drawBars(document.getElementById('dailyChart'), [...days.days].reverse(), { labelKey: 'date', color: '#22c55e' });
}
async function loadSummary() {
  const select = document.getElementById('daySelect');
  const date = select.value;
  const url = date ? `/api/day?date=${encodeURIComponent(date)}` : '/api/today';
  const data = await fetch(url).then(r => r.json());
  const series = await fetch(`/api/timeseries?date=${encodeURIComponent(data.date)}`).then(r => r.json());
  document.getElementById('total').textContent = fmtBytes(data.total_bytes);
  document.getElementById('bytesIn').textContent = fmtBytes(data.bytes_in);
  document.getElementById('bytesOut').textContent = fmtBytes(data.bytes_out);
  document.getElementById('samples').textContent = data.sample_count;
  document.getElementById('csvLink').href = `/api/export.csv?date=${encodeURIComponent(data.date)}`;
  document.getElementById('status').textContent = data.last_sample_at ? `Last sample: ${data.last_sample_at}` : 'No sample yet';
  drawBars(document.getElementById('hourlyChart'), series.series, { labelKey: 'label', color: '#38bdf8' });
  drawBars(document.getElementById('processChart'), data.processes.slice(0, 10), { labelKey: 'process', color: '#a78bfa', horizontal: true });
  const tbody = document.getElementById('rows');
  tbody.innerHTML = '';
  const rows = data.processes || [];
  const max = Math.max(...rows.map(p => p.total_bytes), 1);
  for (const row of rows) {
    const tr = document.createElement('tr');
    const tunnel = row.is_tunnel ? '<span class="pill">tunnel aggregate</span>' : '';
    const share = Math.round((row.total_bytes / max) * 100);
    tr.innerHTML = `<td>${escapeHtml(row.process)} ${tunnel}</td><td>${fmtBytes(row.total_bytes)}</td><td>${fmtBytes(row.bytes_in)}</td><td>${fmtBytes(row.bytes_out)}</td><td><div class="bar"><span style="width:${share}%"></span></div></td><td>${escapeHtml((row.pids || []).join(', '))}</td>`;
    tbody.appendChild(tr);
  }
  if (!rows.length) tbody.innerHTML = '<tr><td colspan="6">No data has been recorded yet.</td></tr>';
  const err = data.last_error ? ` <span class="error">Last error: ${escapeHtml(data.last_error)}</span>` : '';
  document.getElementById('footer').innerHTML = `Database: ${escapeHtml(data.database_path)}${err}`;
}
async function refreshAll() { await loadDays(); await loadSummary(); }
document.getElementById('refreshBtn').addEventListener('click', refreshAll);
document.getElementById('daySelect').addEventListener('change', loadSummary);
window.addEventListener('resize', () => { loadSummary().catch(() => {}); });
refreshAll().catch(err => { document.getElementById('status').textContent = err; });
setInterval(() => { loadSummary().catch(() => {}); }, 5000);
</script>
</body>
</html>
"""


class DashboardServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], data_dir: Path, state: CollectorState):
        super().__init__(server_address, DashboardRequestHandler)
        self.data_dir = data_dir
        self.state = state


class DashboardRequestHandler(BaseHTTPRequestHandler):
    @property
    def dashboard_server(self) -> DashboardServer:
        return cast(DashboardServer, self.server)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - inherited API name
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), format % args))

    def send_bytes(self, body: bytes, *, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload: dict[str, Any], *, status: int = 200) -> None:
        self.send_bytes(
            json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
            content_type="application/json; charset=utf-8",
            status=status,
        )

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/":
            self.send_bytes(DASHBOARD_HTML.encode("utf-8"), content_type="text/html; charset=utf-8")
            return
        if parsed.path == "/health":
            payload = {
                "ok": True,
                "data_dir": str(self.dashboard_server.data_dir),
                "database_path": str(database_path(self.dashboard_server.data_dir)),
                "pid": os.getpid(),
                "collector": self.dashboard_server.state.snapshot(),
            }
            self.send_json(payload)
            return
        if parsed.path == "/api/today":
            self.send_json(summarize_day(self.dashboard_server.data_dir))
            return
        if parsed.path == "/api/day":
            date = first_query_value(query, "date") or day_string()
            self.send_json(summarize_day(self.dashboard_server.data_dir, date))
            return
        if parsed.path == "/api/days":
            self.send_json({"days": list_days(self.dashboard_server.data_dir), "collector": self.dashboard_server.state.snapshot()})
            return
        if parsed.path == "/api/timeseries":
            date = first_query_value(query, "date") or day_string()
            self.send_json({"date": date, "series": timeseries_day(self.dashboard_server.data_dir, date)})
            return
        if parsed.path == "/api/export.csv":
            date = first_query_value(query, "date") or day_string()
            self.send_bytes(export_csv(self.dashboard_server.data_dir, date), content_type="text/csv; charset=utf-8")
            return
        self.send_json({"error": "not found"}, status=404)


def first_query_value(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name) or []
    return values[0] if values else None


def export_csv(data_dir: Path, date: str) -> bytes:
    summary = summarize_day(data_dir, date)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["date", "process", "bytes_in", "bytes_out", "total_bytes", "samples", "pids", "is_tunnel"])
    for row in summary["processes"]:
        writer.writerow(
            [
                summary["date"],
                row["process"],
                row["bytes_in"],
                row["bytes_out"],
                row["total_bytes"],
                row["samples"],
                " ".join(str(pid) for pid in row.get("pids", [])),
                "yes" if row.get("is_tunnel") else "no",
            ]
        )
    return buffer.getvalue().encode("utf-8")


def parse_bind(bind: str) -> tuple[str, int]:
    if ":" not in bind:
        raise ValueError("bind must be HOST:PORT")
    host, port_text = bind.rsplit(":", 1)
    host = host or "127.0.0.1"
    return host, int(port_text)


def collector_loop(
    data_dir: Path,
    state: CollectorState,
    *,
    interval_seconds: int,
    nettop_path: str,
    stop_event: threading.Event,
) -> None:
    while not stop_event.is_set():
        try:
            rows = collect_once(interval_seconds, nettop_path=nettop_path)
            stamp = local_now()
            append_sample_record(data_dir, rows, interval_seconds=interval_seconds, timestamp=stamp)
            state.record_sample(stamp, rows)
        except Exception as exc:  # noqa: BLE001 - this is a resilient background collector
            message = str(exc)
            append_error_record(data_dir, message)
            state.record_error(message)
            stop_event.wait(min(interval_seconds, 30))


def serve(bind: str, data_dir: Path, *, interval_seconds: int, nettop_path: str, collect: bool) -> None:
    init_database(data_dir)
    state = CollectorState()
    stop_event = threading.Event()
    collector: threading.Thread | None = None
    if collect:
        collector = threading.Thread(
            target=collector_loop,
            kwargs={
                "data_dir": data_dir,
                "state": state,
                "interval_seconds": interval_seconds,
                "nettop_path": nettop_path,
                "stop_event": stop_event,
            },
            daemon=True,
        )
        collector.start()

    host, port = parse_bind(bind)
    server = DashboardServer((host, port), data_dir, state)
    actual_host, actual_port = server.server_address[:2]
    print(f"Dashboard: http://{actual_host}:{actual_port}/", flush=True)
    print(f"Data dir:  {data_dir}", flush=True)
    print(f"Database:  {database_path(data_dir)}", flush=True)
    print(f"Collect:   {'on' if collect else 'off'} interval={interval_seconds}s", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...", flush=True)
    finally:
        stop_event.set()
        server.server_close()
        if collector:
            collector.join(timeout=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="macOS per-process network traffic dashboard using nettop and SQLite")
    parser.add_argument("--serve", nargs="?", const=DEFAULT_BIND, metavar="HOST:PORT", help=f"serve dashboard (default {DEFAULT_BIND})")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SECONDS, help="collector interval seconds")
    parser.add_argument("--data-dir", type=Path, default=default_data_dir(), help="directory for the SQLite database")
    parser.add_argument("--nettop", default="nettop", help="path to nettop")
    parser.add_argument("--no-collect", action="store_true", help="serve dashboard without starting the collector")
    parser.add_argument("--init-db", action="store_true", help="initialize the SQLite database and exit")
    parser.add_argument("--collect-once", action="store_true", help="take one nettop sample and append it to the database")
    parser.add_argument("--report", nargs="?", const=day_string(), metavar="YYYY-MM-DD", help="print a CLI report for a day")
    parser.add_argument("--days", action="store_true", help="list days stored in the database")
    parser.add_argument("--top", type=int, default=20, help="number of rows in CLI reports")
    args = parser.parse_args(argv)

    if args.interval < 1:
        parser.error("--interval must be >= 1")

    if args.init_db:
        path = init_database(args.data_dir)
        print(f"Initialized database: {path}")
        return 0

    if args.collect_once:
        rows = collect_once(args.interval, nettop_path=args.nettop)
        path = append_sample_record(args.data_dir, rows, interval_seconds=args.interval)
        print(f"Wrote {len(rows)} process rows to {path}")
        print_report(summarize_day(args.data_dir), top=args.top)
        return 0

    if args.days:
        for day in list_days(args.data_dir):
            print(
                f"{day['date']}  total={human_bytes(day['total_bytes'])}  "
                f"samples={day['sample_count']}  errors={day['error_count']}  {day['database_path']}"
            )
        return 0

    if args.report:
        print_report(summarize_day(args.data_dir, args.report), top=args.top)
        return 0

    if args.serve:
        serve(args.serve, args.data_dir, interval_seconds=args.interval, nettop_path=args.nettop, collect=not args.no_collect)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
