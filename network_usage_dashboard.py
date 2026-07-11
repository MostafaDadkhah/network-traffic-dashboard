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
import tempfile
import threading
import urllib.parse
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable, Sequence, cast

APP_NAME = "NetworkTrafficDashboard"
DEFAULT_BIND = "127.0.0.1:18686"
DEFAULT_INTERVAL_SECONDS = 60
DEFAULT_API_PROCESS_LIMIT = 40
MAX_API_PROCESS_LIMIT = 200
DEFAULT_PID_SAMPLE_LIMIT = 8
MAX_PID_SAMPLE_LIMIT = 50
DEFAULT_SYNC_RETRY_INTERVAL_SECONDS = 900
SCHEMA_VERSION = 2
DATABASE_FILENAME = "network_traffic.sqlite3"
SYNC_DATABASE_URL_ENV = "NETWORK_TRAFFIC_SYNC_DATABASE_URL"
SYNC_PSQL_ENV = "NETWORK_TRAFFIC_SYNC_PSQL"
SYNC_KEYCHAIN_SERVICE_ENV = "NETWORK_TRAFFIC_SYNC_KEYCHAIN_SERVICE"
SYNC_KEYCHAIN_ACCOUNT_ENV = "NETWORK_TRAFFIC_SYNC_KEYCHAIN_ACCOUNT"
SYNC_RETRY_INTERVAL_ENV = "NETWORK_TRAFFIC_SYNC_RETRY_INTERVAL_SECONDS"


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


@dataclass(frozen=True)
class SyncConfig:
    database_url: str | None = None
    psql_path: str = "psql"
    keychain_service: str | None = None
    keychain_account: str | None = None
    prune_after_sync: bool = True
    keep_local_days: int = 0
    connect_timeout: int = 15
    retry_interval_seconds: int = DEFAULT_SYNC_RETRY_INTERVAL_SECONDS

    @property
    def enabled(self) -> bool:
        return bool(self.database_url)


class SyncBackoff:
    def __init__(self, retry_interval_seconds: int) -> None:
        self.retry_interval_seconds = max(0, int(retry_interval_seconds))
        self.next_attempt_at: datetime | None = None

    def should_attempt(self, now: datetime) -> bool:
        return self.next_attempt_at is None or now >= self.next_attempt_at

    def record_success(self) -> None:
        self.next_attempt_at = None

    def record_failure(self, now: datetime) -> datetime:
        self.next_attempt_at = now + timedelta(seconds=self.retry_interval_seconds)
        return self.next_attempt_at


class CollectorState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.last_sample_at: str | None = None
        self.last_error: str | None = None
        self.last_sync_at: str | None = None
        self.last_sync_error: str | None = None
        self.last_sync_days: list[str] = []
        self.next_sync_attempt_at: str | None = None
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

    def record_sync(self, days: list[str], error: str | None = None, next_attempt_at: str | None = None) -> None:
        with self._lock:
            self.last_sync_at = local_now().isoformat(timespec="seconds")
            self.last_sync_error = error
            self.last_sync_days = days
            self.next_sync_attempt_at = next_attempt_at

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "last_sample_at": self.last_sample_at,
                "last_error": self.last_error,
                "last_sync_at": self.last_sync_at,
                "last_sync_error": self.last_sync_error,
                "last_sync_days": self.last_sync_days,
                "next_sync_attempt_at": self.next_sync_attempt_at,
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


def parse_date(value: str) -> datetime.date:
    return datetime.strptime(value, "%Y-%m-%d").date()


def today_cutoff_date(keep_local_days: int, today: str | None = None) -> str:
    current = parse_date(today or day_string())
    return (current - timedelta(days=max(0, keep_local_days))).isoformat()


def redacted_database_url(database_url: str | None) -> str:
    if not database_url:
        return ""
    parsed = urllib.parse.urlparse(database_url)
    if parsed.password is None:
        return database_url
    user = urllib.parse.quote(urllib.parse.unquote(parsed.username or ""), safe="")
    netloc = f"{user}:***@{parsed.hostname or ''}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return urllib.parse.urlunparse(parsed._replace(netloc=netloc))


def postgres_env(sync_config: SyncConfig) -> dict[str, str]:
    if not sync_config.database_url:
        raise ValueError("sync database URL is not configured")
    parsed = urllib.parse.urlparse(sync_config.database_url)
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise ValueError("sync database URL must use postgresql://")
    env = os.environ.copy()
    if parsed.hostname:
        env["PGHOST"] = parsed.hostname
    if parsed.port:
        env["PGPORT"] = str(parsed.port)
    database = urllib.parse.unquote(parsed.path.lstrip("/")) if parsed.path else ""
    if database:
        env["PGDATABASE"] = database
    if parsed.username:
        env["PGUSER"] = urllib.parse.unquote(parsed.username)
    if parsed.password:
        env["PGPASSWORD"] = urllib.parse.unquote(parsed.password)
    elif sync_config.keychain_service and sync_config.keychain_account:
        password = keychain_password(sync_config.keychain_service, sync_config.keychain_account)
        if password:
            env["PGPASSWORD"] = password
    query = urllib.parse.parse_qs(parsed.query)
    query_env = {
        "sslmode": "PGSSLMODE",
        "hostaddr": "PGHOSTADDR",
        "connect_timeout": "PGCONNECT_TIMEOUT",
        "application_name": "PGAPPNAME",
    }
    for key, env_name in query_env.items():
        values = query.get(key)
        if values:
            env[env_name] = values[-1]
    env.setdefault("PGCONNECT_TIMEOUT", str(sync_config.connect_timeout))
    return env


def keychain_password(service: str, account: str) -> str | None:
    if sys.platform != "darwin":
        return None
    try:
        return subprocess.check_output(
            ["security", "find-generic-password", "-w", "-s", service, "-a", account],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except subprocess.CalledProcessError:
        return None


def run_psql(
    sync_config: SyncConfig,
    args: Sequence[str],
    *,
    input_text: str | None = None,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    if not sync_config.enabled:
        raise ValueError("sync database is not configured")
    command = [sync_config.psql_path, "-X", *args]
    try:
        return subprocess.run(
            command,
            input=input_text,
            capture_output=capture,
            text=True,
            env=postgres_env(sync_config),
            check=False,
            timeout=max(1, sync_config.connect_timeout + 5),
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            command,
            124,
            stdout=exc.stdout if isinstance(exc.stdout, str) else "",
            stderr=f"psql timed out after {max(1, sync_config.connect_timeout + 5)} seconds",
        )


def run_psql_checked(sync_config: SyncConfig, args: Sequence[str], *, input_text: str | None = None) -> str:
    completed = run_psql(sync_config, args, input_text=input_text, capture=True)
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or f"psql exited with {completed.returncode}").strip()
        raise RuntimeError(message)
    return completed.stdout


def run_psql_script(sync_config: SyncConfig, sql: str) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".sql", delete=False) as handle:
        handle.write(sql)
        script_path = handle.name
    try:
        run_psql_checked(sync_config, ["-v", "ON_ERROR_STOP=1", "-f", script_path])
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def psql_json_rows(sync_config: SyncConfig, query: str) -> list[dict[str, Any]]:
    sql = f"SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json)::text FROM ({query}) q"
    output = run_psql_checked(sync_config, ["-At", "-v", "ON_ERROR_STOP=1", "-c", sql]).strip()
    if not output:
        return []
    return cast(list[dict[str, Any]], json.loads(output))


def psql_json_one(sync_config: SyncConfig, query: str) -> dict[str, Any]:
    rows = psql_json_rows(sync_config, query)
    return rows[0] if rows else {}


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


REMOTE_SCHEMA_SQL = """
SET client_min_messages TO WARNING;
CREATE TABLE IF NOT EXISTS metadata (
  key text PRIMARY KEY,
  value text NOT NULL
);
CREATE TABLE IF NOT EXISTS samples (
  id bigint PRIMARY KEY,
  ts text NOT NULL,
  date text NOT NULL,
  source text NOT NULL,
  interval_seconds integer NOT NULL,
  total_bytes bigint NOT NULL,
  bytes_in bigint NOT NULL,
  bytes_out bigint NOT NULL,
  process_count integer NOT NULL,
  created_at text NOT NULL
);
CREATE TABLE IF NOT EXISTS process_deltas (
  id bigint PRIMARY KEY,
  sample_id bigint NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
  raw_process text NOT NULL,
  process text NOT NULL,
  pid bigint,
  bytes_in bigint NOT NULL,
  bytes_out bigint NOT NULL,
  total_bytes bigint NOT NULL,
  is_tunnel integer NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS errors (
  id bigint PRIMARY KEY,
  ts text NOT NULL,
  date text NOT NULL,
  error text NOT NULL,
  created_at text NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_date ON samples(date);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE INDEX IF NOT EXISTS idx_process_deltas_sample ON process_deltas(sample_id);
CREATE INDEX IF NOT EXISTS idx_process_deltas_process ON process_deltas(process);
CREATE INDEX IF NOT EXISTS idx_errors_date ON errors(date);
"""

SYNC_TABLES = {
    "samples": [
        "id",
        "ts",
        "date",
        "source",
        "interval_seconds",
        "total_bytes",
        "bytes_in",
        "bytes_out",
        "process_count",
        "created_at",
    ],
    "process_deltas": [
        "id",
        "sample_id",
        "raw_process",
        "process",
        "pid",
        "bytes_in",
        "bytes_out",
        "total_bytes",
        "is_tunnel",
    ],
    "errors": ["id", "ts", "date", "error", "created_at"],
}


def ensure_remote_schema(sync_config: SyncConfig) -> None:
    run_psql_script(sync_config, REMOTE_SCHEMA_SQL)


def csv_payload(rows: Iterable[Sequence[Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    for row in rows:
        writer.writerow(["\\N" if value is None else value for value in row])
    return buffer.getvalue()


def copy_block(table: str, columns: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    if not rows:
        return ""
    return (
        f"COPY tmp_{table} ({', '.join(columns)}) FROM STDIN WITH (FORMAT csv, NULL '\\N');\n"
        + csv_payload(rows)
        + "\\.\n"
    )


def local_day_counts(data_dir: Path, date: str) -> dict[str, int]:
    init_database(data_dir)
    with connect_database(data_dir) as conn:
        samples = int(conn.execute("SELECT COUNT(*) FROM samples WHERE date = ?", (date,)).fetchone()[0] or 0)
        process_deltas = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM process_deltas d
                JOIN samples s ON s.id = d.sample_id
                WHERE s.date = ?
                """,
                (date,),
            ).fetchone()[0]
            or 0
        )
        errors = int(conn.execute("SELECT COUNT(*) FROM errors WHERE date = ?", (date,)).fetchone()[0] or 0)
    return {"samples": samples, "process_deltas": process_deltas, "errors": errors}


def remote_day_counts(sync_config: SyncConfig, date: str) -> dict[str, int]:
    quoted_date = sql_literal(date)
    row = psql_json_one(
        sync_config,
        f"""
        SELECT
          (SELECT COUNT(*) FROM samples WHERE date = {quoted_date})::bigint AS samples,
          (
            SELECT COUNT(*)
            FROM process_deltas d
            JOIN samples s ON s.id = d.sample_id
            WHERE s.date = {quoted_date}
          )::bigint AS process_deltas,
          (SELECT COUNT(*) FROM errors WHERE date = {quoted_date})::bigint AS errors
        """,
    )
    return {
        "samples": int(row.get("samples") or 0),
        "process_deltas": int(row.get("process_deltas") or 0),
        "errors": int(row.get("errors") or 0),
    }


def completed_local_days(data_dir: Path, sync_config: SyncConfig, *, today: str | None = None) -> list[str]:
    cutoff = today_cutoff_date(sync_config.keep_local_days, today)
    init_database(data_dir)
    with connect_database(data_dir) as conn:
        rows = conn.execute(
            """
            SELECT date
            FROM (
              SELECT date FROM samples
              UNION
              SELECT date FROM errors
            )
            WHERE date < ?
            ORDER BY date ASC
            """,
            (cutoff,),
        ).fetchall()
    return [str(row["date"]) for row in rows]


def sync_sql_for_day(data_dir: Path, date: str) -> str:
    init_database(data_dir)
    with connect_database(data_dir) as conn:
        metadata = [tuple(row) for row in conn.execute("SELECT key, value FROM metadata ORDER BY key")]
        samples = [
            tuple(row)
            for row in conn.execute(
                f"SELECT {', '.join(SYNC_TABLES['samples'])} FROM samples WHERE date = ? ORDER BY id",
                (date,),
            )
        ]
        process_deltas = [
            tuple(row)
            for row in conn.execute(
                f"""
                SELECT {', '.join('d.' + column for column in SYNC_TABLES['process_deltas'])}
                FROM process_deltas d
                JOIN samples s ON s.id = d.sample_id
                WHERE s.date = ?
                ORDER BY d.id
                """,
                (date,),
            )
        ]
        errors = [
            tuple(row)
            for row in conn.execute(
                f"SELECT {', '.join(SYNC_TABLES['errors'])} FROM errors WHERE date = ? ORDER BY id",
                (date,),
            )
        ]

    sql = REMOTE_SCHEMA_SQL
    sql += """
CREATE TEMP TABLE tmp_metadata (key text, value text);
CREATE TEMP TABLE tmp_samples (LIKE samples INCLUDING DEFAULTS);
CREATE TEMP TABLE tmp_process_deltas (LIKE process_deltas INCLUDING DEFAULTS);
CREATE TEMP TABLE tmp_errors (LIKE errors INCLUDING DEFAULTS);
"""
    sql += copy_block("metadata", ["key", "value"], metadata)
    sql += copy_block("samples", SYNC_TABLES["samples"], samples)
    sql += copy_block("process_deltas", SYNC_TABLES["process_deltas"], process_deltas)
    sql += copy_block("errors", SYNC_TABLES["errors"], errors)
    sql += """
INSERT INTO metadata (key, value)
SELECT key, value FROM tmp_metadata
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
INSERT INTO samples
SELECT * FROM tmp_samples
ON CONFLICT (id) DO UPDATE SET
  ts = EXCLUDED.ts,
  date = EXCLUDED.date,
  source = EXCLUDED.source,
  interval_seconds = EXCLUDED.interval_seconds,
  total_bytes = EXCLUDED.total_bytes,
  bytes_in = EXCLUDED.bytes_in,
  bytes_out = EXCLUDED.bytes_out,
  process_count = EXCLUDED.process_count,
  created_at = EXCLUDED.created_at;
INSERT INTO process_deltas
SELECT * FROM tmp_process_deltas
ON CONFLICT (id) DO UPDATE SET
  sample_id = EXCLUDED.sample_id,
  raw_process = EXCLUDED.raw_process,
  process = EXCLUDED.process,
  pid = EXCLUDED.pid,
  bytes_in = EXCLUDED.bytes_in,
  bytes_out = EXCLUDED.bytes_out,
  total_bytes = EXCLUDED.total_bytes,
  is_tunnel = EXCLUDED.is_tunnel;
INSERT INTO errors
SELECT * FROM tmp_errors
ON CONFLICT (id) DO UPDATE SET
  ts = EXCLUDED.ts,
  date = EXCLUDED.date,
  error = EXCLUDED.error,
  created_at = EXCLUDED.created_at;
"""
    return sql


def delete_local_day(data_dir: Path, date: str, *, vacuum: bool = True) -> None:
    init_database(data_dir)
    with connect_database(data_dir) as conn:
        conn.execute(
            """
            DELETE FROM process_deltas
            WHERE sample_id IN (SELECT id FROM samples WHERE date = ?)
            """,
            (date,),
        )
        conn.execute("DELETE FROM samples WHERE date = ?", (date,))
        conn.execute("DELETE FROM errors WHERE date = ?", (date,))
    if vacuum:
        with connect_database(data_dir) as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.execute("VACUUM")


def sync_completed_days(data_dir: Path, sync_config: SyncConfig, *, today: str | None = None) -> list[str]:
    if not sync_config.enabled:
        return []
    candidates: list[tuple[str, dict[str, int]]] = []
    for date in completed_local_days(data_dir, sync_config, today=today):
        local_counts = local_day_counts(data_dir, date)
        if sum(local_counts.values()) == 0:
            continue
        candidates.append((date, local_counts))
    if not candidates:
        return []

    synced: list[str] = []
    ensure_remote_schema(sync_config)
    for date, local_counts in candidates:
        run_psql_script(sync_config, sync_sql_for_day(data_dir, date))
        remote_counts = remote_day_counts(sync_config, date)
        missing = [
            name
            for name, count in local_counts.items()
            if int(remote_counts.get(name) or 0) < int(count or 0)
        ]
        if missing:
            raise RuntimeError(f"remote sync verification failed for {date}: {', '.join(missing)}")
        if sync_config.prune_after_sync:
            delete_local_day(data_dir, date)
        synced.append(date)
    return synced


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
    pids: list[int] = []
    seen: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if part.isdigit():
            pid = int(part)
            if pid not in seen:
                seen.add(pid)
                pids.append(pid)
    return pids


def empty_summary(data_dir: Path, date: str) -> dict[str, Any]:
    return {
        "date": date,
        "exists": database_path(data_dir).exists(),
        "database_path": str(database_path(data_dir)),
        "storage": "local",
        "sample_count": 0,
        "error_count": 0,
        "first_sample_at": None,
        "last_sample_at": None,
        "last_error": None,
        "bytes_in": 0,
        "bytes_out": 0,
        "total_bytes": 0,
        "observed_bytes_in": 0,
        "observed_bytes_out": 0,
        "observed_total_bytes": 0,
        "tunnel_bytes_in": 0,
        "tunnel_bytes_out": 0,
        "tunnel_total_bytes": 0,
        "processes": [],
        "tunnel_processes": [],
        "latest_processes": [],
        "latest_tunnel_processes": [],
    }


def normalize_process_rows(rows: Iterable[Any]) -> list[dict[str, Any]]:
    normalized = [dict(row) for row in rows]
    for row in normalized:
        row["bytes_in"] = int(row.get("bytes_in") or 0)
        row["bytes_out"] = int(row.get("bytes_out") or 0)
        row["total_bytes"] = int(row.get("total_bytes") or 0)
        row["samples"] = int(row.get("samples") or 0)
        row["pids"] = parse_pids(row.get("pids"))
        row["pid_count"] = int(row.get("pid_count") or len(row["pids"]))
        row["pids_truncated"] = row["pid_count"] > len(row["pids"])
        row["is_tunnel"] = bool(row.get("is_tunnel"))
    return normalized


def normalize_latest_process_rows(rows: Iterable[Any]) -> list[dict[str, Any]]:
    normalized = [dict(row) for row in rows]
    for row in normalized:
        row["bytes_in"] = int(row.get("bytes_in") or 0)
        row["bytes_out"] = int(row.get("bytes_out") or 0)
        row["total_bytes"] = int(row.get("total_bytes") or 0)
        row["pid"] = int(row["pid"]) if row.get("pid") is not None else None
        row["pids"] = [row["pid"]] if row["pid"] is not None else []
        row["pid_count"] = len(row["pids"])
        row["pids_truncated"] = False
        row["samples"] = 1
        row["is_tunnel"] = bool(row.get("is_tunnel"))
    return normalized


def should_read_remote(sync_config: SyncConfig | None, date: str) -> bool:
    return bool(sync_config and sync_config.enabled and date < day_string())


def summarize_day(
    data_dir: Path,
    date: str | None = None,
    *,
    top_limit: int | None = None,
    pid_limit: int = DEFAULT_PID_SAMPLE_LIMIT,
    sync_config: SyncConfig | None = None,
) -> dict[str, Any]:
    selected_date = date or day_string()
    pid_limit = min(max(int(pid_limit), 0), MAX_PID_SAMPLE_LIMIT)
    if top_limit is not None:
        top_limit = min(max(int(top_limit), 1), MAX_API_PROCESS_LIMIT)
    if should_read_remote(sync_config, selected_date):
        try:
            assert sync_config is not None
            return summarize_day_remote(sync_config, data_dir, selected_date, top_limit=top_limit, pid_limit=pid_limit)
        except Exception:
            # If the optional archive is unavailable, keep the dashboard usable.
            # A pruned local day may still return an empty local summary.
            pass
    init_database(data_dir)
    with connect_database(data_dir) as conn:
        sample_stats = conn.execute(
            """
            SELECT COUNT(*) AS sample_count,
                   MIN(ts) AS first_sample_at,
                   MAX(ts) AS last_sample_at
            FROM samples
            WHERE date = ?
            """,
            (selected_date,),
        ).fetchone()
        traffic_stats = conn.execute(
            """
            SELECT COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.bytes_in ELSE 0 END), 0) AS bytes_in,
                   COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.bytes_out ELSE 0 END), 0) AS bytes_out,
                   COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.total_bytes ELSE 0 END), 0) AS total_bytes,
                   COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.bytes_in ELSE 0 END), 0) AS tunnel_bytes_in,
                   COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.bytes_out ELSE 0 END), 0) AS tunnel_bytes_out,
                   COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.total_bytes ELSE 0 END), 0) AS tunnel_total_bytes,
                   COALESCE(SUM(d.bytes_in), 0) AS observed_bytes_in,
                   COALESCE(SUM(d.bytes_out), 0) AS observed_bytes_out,
                   COALESCE(SUM(d.total_bytes), 0) AS observed_total_bytes
            FROM process_deltas d
            JOIN samples s ON s.id = d.sample_id
            WHERE s.date = ?
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

        process_select = """
            SELECT agg.process,
                   agg.bytes_in,
                   agg.bytes_out,
                   agg.total_bytes,
                   agg.samples,
                   agg.is_tunnel,
                   agg.pid_count,
                   (
                       SELECT GROUP_CONCAT(pid)
                       FROM (
                           SELECT d2.pid AS pid, MAX(d2.id) AS last_seen_id
                           FROM process_deltas d2
                           JOIN samples s2 ON s2.id = d2.sample_id
                           WHERE s2.date = agg.date
                             AND d2.is_tunnel = agg.is_tunnel
                             AND d2.process = agg.process
                             AND d2.pid IS NOT NULL
                           GROUP BY d2.pid
                           ORDER BY last_seen_id DESC
                           LIMIT ?
                       )
                   ) AS pids
            FROM (
                SELECT s.date AS date,
                       d.process AS process,
                       COALESCE(SUM(d.bytes_in), 0) AS bytes_in,
                       COALESCE(SUM(d.bytes_out), 0) AS bytes_out,
                       COALESCE(SUM(d.total_bytes), 0) AS total_bytes,
                       COUNT(*) AS samples,
                       MAX(d.is_tunnel) AS is_tunnel,
                       COUNT(DISTINCT d.pid) AS pid_count
                FROM process_deltas d
                JOIN samples s ON s.id = d.sample_id
                WHERE s.date = ? AND d.is_tunnel = ?
                GROUP BY s.date, d.process
            ) agg
            ORDER BY agg.total_bytes DESC
        """
        process_query = process_select
        params: list[Any] = [pid_limit, selected_date, 0]
        if top_limit is not None:
            process_query += " LIMIT ?"
            params.append(top_limit)
        process_rows = normalize_process_rows(conn.execute(process_query, params))
        tunnel_rows = normalize_process_rows(conn.execute(process_select, (pid_limit, selected_date, 1)))

        latest_sample = conn.execute(
            "SELECT id FROM samples WHERE date = ? ORDER BY ts DESC, id DESC LIMIT 1",
            (selected_date,),
        ).fetchone()
        latest_rows: list[dict[str, Any]] = []
        latest_tunnel_rows: list[dict[str, Any]] = []
        if latest_sample:
            latest_rows = normalize_latest_process_rows(
                conn.execute(
                    """
                    SELECT raw_process, process, pid, bytes_in, bytes_out, total_bytes, is_tunnel
                    FROM process_deltas
                    WHERE sample_id = ? AND is_tunnel = 0
                    ORDER BY total_bytes DESC
                    LIMIT 20
                    """,
                    (latest_sample["id"],),
                )
            )
            latest_tunnel_rows = normalize_latest_process_rows(
                conn.execute(
                    """
                    SELECT raw_process, process, pid, bytes_in, bytes_out, total_bytes, is_tunnel
                    FROM process_deltas
                    WHERE sample_id = ? AND is_tunnel = 1
                    ORDER BY total_bytes DESC
                    LIMIT 20
                    """,
                    (latest_sample["id"],),
                )
            )

    return {
        "date": selected_date,
        "exists": True,
        "database_path": str(database_path(data_dir)),
        "storage": "local",
        "sample_count": int(sample_stats["sample_count"] or 0),
        "error_count": int(error_stats["error_count"] or 0) if error_stats else 0,
        "first_sample_at": sample_stats["first_sample_at"],
        "last_sample_at": sample_stats["last_sample_at"],
        "last_error": error_stats["last_error"] if error_stats else None,
        "bytes_in": int(traffic_stats["bytes_in"] or 0),
        "bytes_out": int(traffic_stats["bytes_out"] or 0),
        "total_bytes": int(traffic_stats["total_bytes"] or 0),
        "observed_bytes_in": int(traffic_stats["observed_bytes_in"] or 0),
        "observed_bytes_out": int(traffic_stats["observed_bytes_out"] or 0),
        "observed_total_bytes": int(traffic_stats["observed_total_bytes"] or 0),
        "tunnel_bytes_in": int(traffic_stats["tunnel_bytes_in"] or 0),
        "tunnel_bytes_out": int(traffic_stats["tunnel_bytes_out"] or 0),
        "tunnel_total_bytes": int(traffic_stats["tunnel_total_bytes"] or 0),
        "processes": process_rows,
        "tunnel_processes": tunnel_rows,
        "latest_processes": latest_rows,
        "latest_tunnel_processes": latest_tunnel_rows,
    }


def summarize_day_remote(
    sync_config: SyncConfig,
    data_dir: Path,
    date: str,
    *,
    top_limit: int | None = None,
    pid_limit: int = DEFAULT_PID_SAMPLE_LIMIT,
) -> dict[str, Any]:
    pid_limit = min(max(int(pid_limit), 0), MAX_PID_SAMPLE_LIMIT)
    if top_limit is not None:
        top_limit = min(max(int(top_limit), 1), MAX_API_PROCESS_LIMIT)
    selected_date = sql_literal(date)
    sample_stats = psql_json_one(
        sync_config,
        f"""
        SELECT COUNT(*)::bigint AS sample_count,
               MIN(ts) AS first_sample_at,
               MAX(ts) AS last_sample_at
        FROM samples
        WHERE date = {selected_date}
        """,
    )
    error_stats = psql_json_one(
        sync_config,
        f"""
        SELECT COUNT(*)::bigint AS error_count, MAX(error) AS last_error
        FROM errors
        WHERE date = {selected_date}
        """,
    )
    if int(sample_stats.get("sample_count") or 0) == 0:
        summary = empty_summary(data_dir, date)
        summary["exists"] = True
        summary["database_path"] = redacted_database_url(sync_config.database_url)
        summary["storage"] = "remote"
        summary["error_count"] = int(error_stats.get("error_count") or 0)
        summary["last_error"] = error_stats.get("last_error")
        return summary

    traffic_stats = psql_json_one(
        sync_config,
        f"""
        SELECT COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.bytes_in ELSE 0 END), 0)::bigint AS bytes_in,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.bytes_out ELSE 0 END), 0)::bigint AS bytes_out,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.total_bytes ELSE 0 END), 0)::bigint AS total_bytes,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.bytes_in ELSE 0 END), 0)::bigint AS tunnel_bytes_in,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.bytes_out ELSE 0 END), 0)::bigint AS tunnel_bytes_out,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.total_bytes ELSE 0 END), 0)::bigint AS tunnel_total_bytes,
               COALESCE(SUM(d.bytes_in), 0)::bigint AS observed_bytes_in,
               COALESCE(SUM(d.bytes_out), 0)::bigint AS observed_bytes_out,
               COALESCE(SUM(d.total_bytes), 0)::bigint AS observed_total_bytes
        FROM process_deltas d
        JOIN samples s ON s.id = d.sample_id
        WHERE s.date = {selected_date}
        """,
    )

    limit_sql = f" LIMIT {int(top_limit)}" if top_limit is not None else ""
    pid_limit_sql = max(0, int(pid_limit))
    process_select = f"""
        SELECT agg.process,
               agg.bytes_in,
               agg.bytes_out,
               agg.total_bytes,
               agg.samples,
               agg.is_tunnel,
               agg.pid_count,
               limited_pids.pids
        FROM (
            SELECT s.date AS date,
                   d.process AS process,
                   COALESCE(SUM(d.bytes_in), 0)::bigint AS bytes_in,
                   COALESCE(SUM(d.bytes_out), 0)::bigint AS bytes_out,
                   COALESCE(SUM(d.total_bytes), 0)::bigint AS total_bytes,
                   COUNT(*)::bigint AS samples,
                   MAX(d.is_tunnel)::integer AS is_tunnel,
                   COUNT(DISTINCT d.pid)::bigint AS pid_count
            FROM process_deltas d
            JOIN samples s ON s.id = d.sample_id
            WHERE s.date = {selected_date} AND d.is_tunnel = {{is_tunnel}}
            GROUP BY s.date, d.process
        ) agg
        LEFT JOIN LATERAL (
            SELECT STRING_AGG(pid_text, ',') AS pids
            FROM (
                SELECT d2.pid::text AS pid_text, MAX(d2.id) AS last_seen_id
                FROM process_deltas d2
                JOIN samples s2 ON s2.id = d2.sample_id
                WHERE s2.date = agg.date
                  AND d2.is_tunnel = agg.is_tunnel
                  AND d2.process = agg.process
                  AND d2.pid IS NOT NULL
                GROUP BY d2.pid
                ORDER BY last_seen_id DESC
                LIMIT {pid_limit_sql}
            ) p
        ) limited_pids ON TRUE
        ORDER BY agg.total_bytes DESC
    """
    process_rows = normalize_process_rows(psql_json_rows(sync_config, process_select.format(is_tunnel=0) + limit_sql))
    tunnel_rows = normalize_process_rows(psql_json_rows(sync_config, process_select.format(is_tunnel=1)))

    latest_sample = psql_json_one(
        sync_config,
        f"SELECT id FROM samples WHERE date = {selected_date} ORDER BY ts DESC, id DESC LIMIT 1",
    )
    latest_rows: list[dict[str, Any]] = []
    latest_tunnel_rows: list[dict[str, Any]] = []
    if latest_sample.get("id") is not None:
        sample_id = int(latest_sample["id"])
        latest_query = f"""
            SELECT raw_process, process, pid, bytes_in, bytes_out, total_bytes, is_tunnel
            FROM process_deltas
            WHERE sample_id = {sample_id} AND is_tunnel = {{is_tunnel}}
            ORDER BY total_bytes DESC
            LIMIT 20
        """
        latest_rows = normalize_latest_process_rows(psql_json_rows(sync_config, latest_query.format(is_tunnel=0)))
        latest_tunnel_rows = normalize_latest_process_rows(psql_json_rows(sync_config, latest_query.format(is_tunnel=1)))

    return {
        "date": date,
        "exists": True,
        "database_path": redacted_database_url(sync_config.database_url),
        "storage": "remote",
        "sample_count": int(sample_stats.get("sample_count") or 0),
        "error_count": int(error_stats.get("error_count") or 0),
        "first_sample_at": sample_stats.get("first_sample_at"),
        "last_sample_at": sample_stats.get("last_sample_at"),
        "last_error": error_stats.get("last_error"),
        "bytes_in": int(traffic_stats.get("bytes_in") or 0),
        "bytes_out": int(traffic_stats.get("bytes_out") or 0),
        "total_bytes": int(traffic_stats.get("total_bytes") or 0),
        "observed_bytes_in": int(traffic_stats.get("observed_bytes_in") or 0),
        "observed_bytes_out": int(traffic_stats.get("observed_bytes_out") or 0),
        "observed_total_bytes": int(traffic_stats.get("observed_total_bytes") or 0),
        "tunnel_bytes_in": int(traffic_stats.get("tunnel_bytes_in") or 0),
        "tunnel_bytes_out": int(traffic_stats.get("tunnel_bytes_out") or 0),
        "tunnel_total_bytes": int(traffic_stats.get("tunnel_total_bytes") or 0),
        "processes": process_rows,
        "tunnel_processes": tunnel_rows,
        "latest_processes": latest_rows,
        "latest_tunnel_processes": latest_tunnel_rows,
    }


def list_days_local(data_dir: Path) -> list[dict[str, Any]]:
    init_database(data_dir)
    with connect_database(data_dir) as conn:
        day_map: dict[str, dict[str, Any]] = {}
        for row in conn.execute(
            """
            SELECT s.date AS date,
                   COUNT(DISTINCT s.id) AS sample_count,
                   COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.bytes_in ELSE 0 END), 0) AS bytes_in,
                   COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.bytes_out ELSE 0 END), 0) AS bytes_out,
                   COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.total_bytes ELSE 0 END), 0) AS total_bytes,
                   COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.bytes_in ELSE 0 END), 0) AS tunnel_bytes_in,
                   COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.bytes_out ELSE 0 END), 0) AS tunnel_bytes_out,
                   COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.total_bytes ELSE 0 END), 0) AS tunnel_total_bytes,
                   COALESCE(SUM(d.total_bytes), 0) AS observed_total_bytes,
                   MAX(s.ts) AS last_sample_at
            FROM samples s
            LEFT JOIN process_deltas d ON d.sample_id = s.id
            GROUP BY s.date
            """
        ):
            day_map[row["date"]] = {
                "date": row["date"],
                "database_path": str(database_path(data_dir)),
                "storage": "local",
                "sample_count": int(row["sample_count"] or 0),
                "error_count": 0,
                "total_bytes": int(row["total_bytes"] or 0),
                "bytes_in": int(row["bytes_in"] or 0),
                "bytes_out": int(row["bytes_out"] or 0),
                "tunnel_bytes_in": int(row["tunnel_bytes_in"] or 0),
                "tunnel_bytes_out": int(row["tunnel_bytes_out"] or 0),
                "tunnel_total_bytes": int(row["tunnel_total_bytes"] or 0),
                "observed_total_bytes": int(row["observed_total_bytes"] or 0),
                "last_sample_at": row["last_sample_at"],
            }
        for row in conn.execute("SELECT date, COUNT(*) AS error_count FROM errors GROUP BY date"):
            entry = day_map.setdefault(
                row["date"],
                {
                    "date": row["date"],
                    "database_path": str(database_path(data_dir)),
                    "storage": "local",
                    "sample_count": 0,
                    "error_count": 0,
                    "total_bytes": 0,
                    "bytes_in": 0,
                    "bytes_out": 0,
                    "tunnel_bytes_in": 0,
                    "tunnel_bytes_out": 0,
                    "tunnel_total_bytes": 0,
                    "observed_total_bytes": 0,
                    "last_sample_at": None,
                },
            )
            entry["error_count"] = int(row["error_count"] or 0)
    return sorted(day_map.values(), key=lambda item: item["date"], reverse=True)


def list_days_remote(sync_config: SyncConfig) -> list[dict[str, Any]]:
    rows = psql_json_rows(
        sync_config,
        """
        SELECT s.date AS date,
               COUNT(DISTINCT s.id)::bigint AS sample_count,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.bytes_in ELSE 0 END), 0)::bigint AS bytes_in,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.bytes_out ELSE 0 END), 0)::bigint AS bytes_out,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.total_bytes ELSE 0 END), 0)::bigint AS total_bytes,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.bytes_in ELSE 0 END), 0)::bigint AS tunnel_bytes_in,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.bytes_out ELSE 0 END), 0)::bigint AS tunnel_bytes_out,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.total_bytes ELSE 0 END), 0)::bigint AS tunnel_total_bytes,
               COALESCE(SUM(d.total_bytes), 0)::bigint AS observed_total_bytes,
               MAX(s.ts) AS last_sample_at
        FROM samples s
        LEFT JOIN process_deltas d ON d.sample_id = s.id
        GROUP BY s.date
        """,
    )
    day_map: dict[str, dict[str, Any]] = {}
    for row in rows:
        day_map[str(row["date"])] = {
            "date": row["date"],
            "database_path": redacted_database_url(sync_config.database_url),
            "storage": "remote",
            "sample_count": int(row.get("sample_count") or 0),
            "error_count": 0,
            "total_bytes": int(row.get("total_bytes") or 0),
            "bytes_in": int(row.get("bytes_in") or 0),
            "bytes_out": int(row.get("bytes_out") or 0),
            "tunnel_bytes_in": int(row.get("tunnel_bytes_in") or 0),
            "tunnel_bytes_out": int(row.get("tunnel_bytes_out") or 0),
            "tunnel_total_bytes": int(row.get("tunnel_total_bytes") or 0),
            "observed_total_bytes": int(row.get("observed_total_bytes") or 0),
            "last_sample_at": row.get("last_sample_at"),
        }
    for row in psql_json_rows(sync_config, "SELECT date, COUNT(*)::bigint AS error_count FROM errors GROUP BY date"):
        entry = day_map.setdefault(
            str(row["date"]),
            {
                "date": row["date"],
                "database_path": redacted_database_url(sync_config.database_url),
                "storage": "remote",
                "sample_count": 0,
                "error_count": 0,
                "total_bytes": 0,
                "bytes_in": 0,
                "bytes_out": 0,
                "tunnel_bytes_in": 0,
                "tunnel_bytes_out": 0,
                "tunnel_total_bytes": 0,
                "observed_total_bytes": 0,
                "last_sample_at": None,
            },
        )
        entry["error_count"] = int(row.get("error_count") or 0)
    return sorted(day_map.values(), key=lambda item: item["date"], reverse=True)


def list_days(data_dir: Path, *, sync_config: SyncConfig | None = None) -> list[dict[str, Any]]:
    local_days = list_days_local(data_dir)
    if not sync_config or not sync_config.enabled:
        return local_days
    try:
        remote_days = list_days_remote(sync_config)
    except Exception:
        return local_days
    today = day_string()
    merged: dict[str, dict[str, Any]] = {}
    for day in local_days:
        merged[day["date"]] = day
    for day in remote_days:
        if str(day["date"]) < today:
            merged[str(day["date"])] = day
    return sorted(merged.values(), key=lambda item: item["date"], reverse=True)


def timeseries_day(data_dir: Path, date: str | None = None, *, sync_config: SyncConfig | None = None) -> list[dict[str, Any]]:
    selected_date = date or day_string()
    if should_read_remote(sync_config, selected_date):
        try:
            return timeseries_day_remote(sync_config, selected_date)
        except Exception:
            pass
    init_database(data_dir)
    with connect_database(data_dir) as conn:
        rows = [
            dict(row)
            for row in conn.execute(
                """
                SELECT substr(s.ts, 12, 2) AS hour,
                       COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.bytes_in ELSE 0 END), 0) AS bytes_in,
                       COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.bytes_out ELSE 0 END), 0) AS bytes_out,
                       COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.total_bytes ELSE 0 END), 0) AS total_bytes,
                       COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.total_bytes ELSE 0 END), 0) AS tunnel_total_bytes,
                       COALESCE(SUM(d.total_bytes), 0) AS observed_total_bytes,
                       COUNT(DISTINCT s.id) AS sample_count
                FROM samples s
                LEFT JOIN process_deltas d ON d.sample_id = s.id
                WHERE s.date = ?
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
        row["tunnel_total_bytes"] = int(row["tunnel_total_bytes"] or 0)
        row["observed_total_bytes"] = int(row["observed_total_bytes"] or 0)
        row["sample_count"] = int(row["sample_count"] or 0)
    return rows


def timeseries_day_remote(sync_config: SyncConfig, date: str) -> list[dict[str, Any]]:
    selected_date = sql_literal(date)
    rows = psql_json_rows(
        sync_config,
        f"""
        SELECT substr(s.ts, 12, 2) AS hour,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.bytes_in ELSE 0 END), 0)::bigint AS bytes_in,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.bytes_out ELSE 0 END), 0)::bigint AS bytes_out,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 0 THEN d.total_bytes ELSE 0 END), 0)::bigint AS total_bytes,
               COALESCE(SUM(CASE WHEN d.is_tunnel = 1 THEN d.total_bytes ELSE 0 END), 0)::bigint AS tunnel_total_bytes,
               COALESCE(SUM(d.total_bytes), 0)::bigint AS observed_total_bytes,
               COUNT(DISTINCT s.id)::bigint AS sample_count
        FROM samples s
        LEFT JOIN process_deltas d ON d.sample_id = s.id
        WHERE s.date = {selected_date}
        GROUP BY hour
        ORDER BY hour ASC
        """,
    )
    for row in rows:
        row["label"] = f"{row['hour']}:00"
        row["bytes_in"] = int(row.get("bytes_in") or 0)
        row["bytes_out"] = int(row.get("bytes_out") or 0)
        row["total_bytes"] = int(row.get("total_bytes") or 0)
        row["tunnel_total_bytes"] = int(row.get("tunnel_total_bytes") or 0)
        row["observed_total_bytes"] = int(row.get("observed_total_bytes") or 0)
        row["sample_count"] = int(row.get("sample_count") or 0)
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
        "App-attributed total: "
        f"{human_bytes(summary['total_bytes'])} "
        f"(in {human_bytes(summary['bytes_in'])}, out {human_bytes(summary['bytes_out'])})"
    )
    print(
        "Tunnel aggregate excluded from app ranking: "
        f"{human_bytes(summary.get('tunnel_total_bytes', 0))}"
    )
    print(f"Observed raw total including tunnel aggregate: {human_bytes(summary.get('observed_total_bytes', 0))}")
    print(f"Samples: {summary['sample_count']}  Errors: {summary['error_count']}")
    print("")
    print(f"{'app process':32s} {'total':>12s} {'in':>12s} {'out':>12s}  pids")
    print("-" * 82)
    for row in summary["processes"][:top]:
        pids = ",".join(str(pid) for pid in row.get("pids", [])[:6])
        print(
            f"{row['process'][:32]:32s} "
            f"{human_bytes(row['total_bytes']):>12s} "
            f"{human_bytes(row['bytes_in']):>12s} "
            f"{human_bytes(row['bytes_out']):>12s}  "
            f"{pids}"
        )


FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0b1020"/>
      <stop offset="1" stop-color="#172554"/>
    </linearGradient>
    <linearGradient id="signal" x1="10" y1="46" x2="54" y2="18">
      <stop offset="0" stop-color="#22c55e"/>
      <stop offset="0.55" stop-color="#38bdf8"/>
      <stop offset="1" stop-color="#a78bfa"/>
    </linearGradient>
    <filter id="glow" x="-40%" y="-40%" width="180%" height="180%">
      <feGaussianBlur stdDeviation="2.2" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>
  <rect width="64" height="64" rx="15" fill="url(#bg)"/>
  <path d="M13 45 C22 29 29 39 36 25 S49 22 53 12" fill="none" stroke="#13203c" stroke-width="14" stroke-linecap="round"/>
  <path d="M13 45 C22 29 29 39 36 25 S49 22 53 12" fill="none" stroke="url(#signal)" stroke-width="6" stroke-linecap="round" filter="url(#glow)"/>
  <circle cx="13" cy="45" r="6" fill="#22c55e"/>
  <circle cx="36" cy="25" r="6" fill="#38bdf8"/>
  <circle cx="53" cy="12" r="6" fill="#a78bfa"/>
  <path d="M16 53 H48" stroke="#38bdf8" stroke-width="4" stroke-linecap="round" opacity="0.75"/>
</svg>
"""


DASHBOARD_HTML = """<!doctype html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Network Traffic Dashboard</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <meta name="theme-color" content="#0b1020">
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
    input[type="date"], button, a.button { background: #18233d; color: #e7edf7; border: 1px solid #34425f; border-radius: 10px; padding: 9px 12px; text-decoration: none; }
    input[type="date"] { color-scheme: dark; min-width: 150px; }
    button:hover, a.button:hover { background: #22304f; cursor: pointer; }
    button:disabled { opacity: .45; cursor: not-allowed; }
    .charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); gap: 14px; margin: 18px 0; }
    .chart-card { position: relative; background: #11182c; border: 1px solid #25304a; border-radius: 14px; padding: 16px; }
    .chart-title { margin: 0 0 10px; color: #c7d2fe; font-size: 14px; }
    canvas { width: 100%; height: 250px; display: block; }
    .chart-tooltip { position: fixed; z-index: 20; pointer-events: none; min-width: 170px; padding: 10px 12px; border-radius: 12px; border: 1px solid #405174; background: rgba(9, 14, 28, .96); box-shadow: 0 18px 44px rgba(0, 0, 0, .38); color: #e7edf7; font-size: 12px; opacity: 0; transform: translate(10px, 10px); transition: opacity .08s ease; }
    .chart-tooltip.visible { opacity: 1; }
    .chart-tooltip .tooltip-title { margin-bottom: 7px; color: #c7d2fe; font-weight: 700; }
    .chart-tooltip .tooltip-row { display: flex; justify-content: space-between; gap: 18px; margin-top: 4px; color: #aebddb; }
    .chart-tooltip .tooltip-row strong { color: #e7edf7; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; background: #11182c; border: 1px solid #25304a; border-radius: 14px; overflow: hidden; }
    th, td { padding: 11px 12px; border-bottom: 1px solid #202a42; text-align: left; }
    th { background: #151f38; color: #aebddb; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
    tr:last-child td { border-bottom: none; }
    .pids { max-width: 210px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: #b7c4df; }
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
    <div class="muted">Pre-tunnel app-attributed traffic from nettop. MacPacketTunnel and Shadowrocket are transport aggregates and are excluded from app rankings.</div>
  </header>
  <main>
    <div class="toolbar">
      <label>Date: <input id="datePicker" type="date" aria-label="Selected dashboard date"></label>
      <button id="previousDayBtn" title="Go to previous recorded day">Previous day</button>
      <button id="nextDayBtn" title="Go to next recorded day">Next day</button>
      <button id="latestDayBtn" title="Go to latest recorded day">Latest day</button>
      <button id="refreshBtn">Refresh</button>
      <a id="csvLink" class="button" href="#">CSV export</a>
      <span id="status" class="muted"></span>
    </div>
    <section class="cards">
      <div class="card"><div class="label">App-attributed total</div><div id="total" class="value">-</div></div>
      <div class="card"><div class="label">App download</div><div id="bytesIn" class="value">-</div></div>
      <div class="card"><div class="label">App upload</div><div id="bytesOut" class="value">-</div></div>
      <div class="card"><div class="label">Tunnel aggregate excluded</div><div id="tunnelTotal" class="value">-</div></div>
      <div class="card"><div class="label">Samples</div><div id="samples" class="value">-</div></div>
    </section>
    <section class="charts">
      <div class="chart-card"><h2 class="chart-title">Daily app-attributed totals</h2><canvas id="dailyChart"></canvas></div>
      <div class="chart-card"><h2 class="chart-title">Hourly app-attributed traffic</h2><canvas id="hourlyChart"></canvas></div>
      <div class="chart-card"><h2 class="chart-title">Top app processes before tunnel</h2><canvas id="processChart"></canvas></div>
    </section>
    <table>
      <thead><tr><th>App process</th><th>Total</th><th>Download</th><th>Upload</th><th>Share</th><th>PID sample</th></tr></thead>
      <tbody id="rows"><tr><td colspan="6">Loading...</td></tr></tbody>
    </table>
    <footer id="footer"></footer>
  </main>
  <div id="chartTooltip" class="chart-tooltip" role="status" aria-live="polite"></div>
<script>
const fmtBytes = (value) => {
  let n = Number(value || 0);
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  for (const unit of units) {
    if (Math.abs(n) < 1024 || unit === 'TB') return unit === 'B' ? `${Math.round(n)} ${unit}` : `${n.toFixed(1)} ${unit}`;
    n /= 1024;
  }
};
const formatDateLabel = (value) => {
  const parts = String(value || '').split('-');
  return parts.length === 3 ? `${parts[1]}/${parts[2]}` : String(value || '').slice(0, 8);
};
const escapeHtml = (s) => String(s).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const DASHBOARD_TOP_LIMIT = 40;
const PID_SAMPLE_LIMIT = 8;
const SUMMARY_REFRESH_MS = 30000;
const DAYS_REFRESH_MS = 120000;
async function fetchJson(url) {
  const response = await fetch(url);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
  return payload;
}
function formatPids(row) {
  const pids = row.pids || [];
  const pidCount = Number(row.pid_count || pids.length || 0);
  if (!pidCount) return '';
  const shown = pids.join(', ');
  const more = pidCount - pids.length;
  if (more > 0) return `${shown}${shown ? ' ' : ''}+${more} more`;
  return shown;
}
const chartTooltip = document.getElementById('chartTooltip');
function tooltipHtml(item, title) {
  return `<div class="tooltip-title">${escapeHtml(title)}</div>` +
    `<div class="tooltip-row"><span>Total</span><strong>${fmtBytes(item.total_bytes)}</strong></div>` +
    `<div class="tooltip-row"><span>Download</span><strong>${fmtBytes(item.bytes_in)}</strong></div>` +
    `<div class="tooltip-row"><span>Upload</span><strong>${fmtBytes(item.bytes_out)}</strong></div>`;
}
function placeTooltip(event) {
  const margin = 14;
  const rect = chartTooltip.getBoundingClientRect();
  let left = event.clientX + 14;
  let top = event.clientY + 14;
  if (left + rect.width + margin > window.innerWidth) left = event.clientX - rect.width - 14;
  if (top + rect.height + margin > window.innerHeight) top = event.clientY - rect.height - 14;
  chartTooltip.style.left = `${Math.max(margin, left)}px`;
  chartTooltip.style.top = `${Math.max(margin, top)}px`;
}
function hideTooltip() {
  chartTooltip.classList.remove('visible');
}
function attachChartTooltip(canvas) {
  if (canvas.dataset.tooltipReady === '1') return;
  canvas.dataset.tooltipReady = '1';
  canvas.addEventListener('mousemove', event => {
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    const regions = canvas.__chartHitRegions || [];
    const hit = regions.find(region => x >= region.x && x <= region.x + region.width && y >= region.y && y <= region.y + region.height);
    if (!hit) {
      hideTooltip();
      return;
    }
    chartTooltip.innerHTML = tooltipHtml(hit.item, hit.label);
    chartTooltip.classList.add('visible');
    placeTooltip(event);
  });
  canvas.addEventListener('mouseleave', hideTooltip);
}
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
  attachChartTooltip(canvas);
  const { ctx, width, height } = prepareCanvas(canvas);
  const hitRegions = [];
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = '#97a5c0';
  ctx.font = '12px -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif';
  if (!items.length) {
    canvas.__chartHitRegions = [];
    ctx.fillText('No data yet', 14, 28);
    return;
  }
  const labelKey = options.labelKey || 'label';
  const valueKey = options.valueKey || 'total_bytes';
  const color = options.color || '#38bdf8';
  const labelFormatter = options.labelFormatter || ((item) => String(item[labelKey]));
  const max = Math.max(...items.map(item => Number(item[valueKey] || 0)), 1);
  const padLeft = options.horizontal ? 112 : 34;
  const padBottom = options.horizontal ? 34 : (options.padBottom || 58);
  const padTop = 18;
  const chartW = width - padLeft - 12;
  const chartH = height - padTop - padBottom;
  const labelMinWidth = options.labelMinWidth || 48;
  const labelEvery = options.labelEvery || Math.max(1, Math.ceil(items.length / Math.max(1, Math.floor(chartW / labelMinWidth))));
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
      const label = String(labelFormatter(item, idx));
      ctx.fillStyle = '#9fb0d0';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'alphabetic';
      ctx.fillText(label.slice(0, 16), 8, y + barH * 0.75);
      ctx.fillStyle = color;
      ctx.fillRect(padLeft, y, barW, barH);
      hitRegions.push({ x: 0, y, width: Math.max(padLeft + barW, padLeft + 14), height: barH, item, label });
      ctx.fillStyle = '#e7edf7';
      ctx.fillText(fmtBytes(value), Math.min(padLeft + barW + 6, width - 76), y + barH * 0.75);
    });
    canvas.__chartHitRegions = hitRegions;
    return;
  }
  const gap = Math.max(2, Math.min(8, chartW / Math.max(items.length * 8, 1)));
  const barW = Math.max(2, (chartW - gap * (items.length - 1)) / items.length);
  let lastLabelIndex = -labelEvery;
  items.forEach((item, idx) => {
    const value = Number(item[valueKey] || 0);
    const barH = (value / max) * chartH;
    const x = padLeft + idx * (barW + gap);
    const y = padTop + chartH - barH;
    const label = String(labelFormatter(item, idx));
    ctx.fillStyle = color;
    ctx.fillRect(x, y, barW, barH);
    hitRegions.push({ x, y, width: barW, height: Math.max(3, barH), item, label });
    if (idx % labelEvery === 0 || (idx === items.length - 1 && idx - lastLabelIndex >= labelEvery)) {
      lastLabelIndex = idx;
      ctx.fillStyle = '#9fb0d0';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(label.slice(0, options.maxLabelChars || 8), x + barW / 2, padTop + chartH + 10);
    }
  });
  canvas.__chartHitRegions = hitRegions;
  ctx.fillStyle = '#e7edf7';
  ctx.textAlign = 'left';
  ctx.textBaseline = 'alphabetic';
  ctx.fillText(fmtBytes(max), padLeft + 6, padTop + 12);
}
let recordedDays = [];
let recordedDateValues = [];
let collectorState = {};
let syncState = {};
const datePicker = document.getElementById('datePicker');
const previousDayBtn = document.getElementById('previousDayBtn');
const nextDayBtn = document.getElementById('nextDayBtn');
const latestDayBtn = document.getElementById('latestDayBtn');
function latestRecordedDate() {
  return recordedDateValues.length ? recordedDateValues[recordedDateValues.length - 1] : '';
}
function updateDateNavButtons() {
  const current = datePicker.value || latestRecordedDate();
  const hasPrevious = recordedDateValues.some(day => day < current);
  const hasNext = recordedDateValues.some(day => day > current);
  previousDayBtn.disabled = !hasPrevious;
  nextDayBtn.disabled = !hasNext;
  latestDayBtn.disabled = !latestRecordedDate() || current === latestRecordedDate();
}
function updateDatePickerBounds() {
  if (!recordedDateValues.length) {
    datePicker.removeAttribute('min');
    datePicker.removeAttribute('max');
    updateDateNavButtons();
    return;
  }
  datePicker.min = recordedDateValues[0];
  datePicker.max = recordedDateValues[recordedDateValues.length - 1];
  updateDateNavButtons();
}
function moveRecordedDay(delta) {
  if (!recordedDateValues.length) return;
  const current = datePicker.value || latestRecordedDate();
  const exactIndex = recordedDateValues.indexOf(current);
  let target = '';
  if (exactIndex >= 0) {
    target = recordedDateValues[exactIndex + delta] || '';
  } else if (delta < 0) {
    target = [...recordedDateValues].reverse().find(day => day < current) || '';
  } else {
    target = recordedDateValues.find(day => day > current) || '';
  }
  if (!target) return;
  datePicker.value = target;
  loadSummary().catch(err => { document.getElementById('status').textContent = err; });
}
async function loadDays() {
  const days = await fetchJson('/api/days');
  const previous = datePicker.value;
  recordedDays = days.days || [];
  collectorState = days.collector || {};
  syncState = days.sync || {};
  recordedDateValues = recordedDays.map(day => day.date).sort();
  if (!recordedDateValues.length) {
    datePicker.value = '';
    drawBars(document.getElementById('dailyChart'), []);
    updateDatePickerBounds();
    return;
  }
  datePicker.value = previous || latestRecordedDate();
  updateDatePickerBounds();
  drawBars(document.getElementById('dailyChart'), [...recordedDays].reverse(), {
    labelKey: 'date',
    color: '#22c55e',
    labelFormatter: item => formatDateLabel(item.date),
    labelMinWidth: 56,
    maxLabelChars: 5,
  });
}
async function loadSummary() {
  const date = datePicker.value;
  const params = `top=${DASHBOARD_TOP_LIMIT}&pids=${PID_SAMPLE_LIMIT}`;
  const url = date ? `/api/day?date=${encodeURIComponent(date)}&${params}` : `/api/today?${params}`;
  const data = await fetchJson(url);
  const series = await fetchJson(`/api/timeseries?date=${encodeURIComponent(data.date)}`);
  if (!datePicker.value && data.date) datePicker.value = data.date;
  updateDateNavButtons();
  document.getElementById('total').textContent = fmtBytes(data.total_bytes);
  document.getElementById('bytesIn').textContent = fmtBytes(data.bytes_in);
  document.getElementById('bytesOut').textContent = fmtBytes(data.bytes_out);
  document.getElementById('tunnelTotal').textContent = fmtBytes(data.tunnel_total_bytes);
  document.getElementById('samples').textContent = data.sample_count;
  document.getElementById('csvLink').href = `/api/export.csv?date=${encodeURIComponent(data.date)}`;
  document.getElementById('status').textContent = data.last_sample_at ? `Last sample: ${data.last_sample_at}` : `No samples for ${data.date}`;
  drawBars(document.getElementById('hourlyChart'), series.series, { labelKey: 'label', color: '#38bdf8', labelMinWidth: 42, maxLabelChars: 5 });
  drawBars(document.getElementById('processChart'), data.processes.slice(0, 10), { labelKey: 'process', color: '#a78bfa', horizontal: true });
  const tbody = document.getElementById('rows');
  tbody.innerHTML = '';
  const rows = data.processes || [];
  const max = Math.max(...rows.map(p => p.total_bytes), 1);
  for (const row of rows) {
    const tr = document.createElement('tr');
    const share = Math.round((row.total_bytes / max) * 100);
    const pidText = formatPids(row);
    const pidTitle = row.pid_count ? `${row.pid_count} distinct PID${row.pid_count === 1 ? '' : 's'}` : '';
    tr.innerHTML = `<td>${escapeHtml(row.process)}</td><td>${fmtBytes(row.total_bytes)}</td><td>${fmtBytes(row.bytes_in)}</td><td>${fmtBytes(row.bytes_out)}</td><td><div class="bar"><span style="width:${share}%"></span></div></td><td class="pids" title="${escapeHtml(pidTitle)}">${escapeHtml(pidText)}</td>`;
    tbody.appendChild(tr);
  }
  if (!rows.length) tbody.innerHTML = '<tr><td colspan="6">No data has been recorded yet.</td></tr>';
  const err = data.last_error ? ` <span class="error">Last error: ${escapeHtml(data.last_error)}</span>` : '';
  const syncErr = collectorState.last_sync_error ? ` <span class="error">Sync error: ${escapeHtml(collectorState.last_sync_error)}</span>` : '';
  const syncRetry = collectorState.next_sync_attempt_at ? ` Next sync retry: ${escapeHtml(collectorState.next_sync_attempt_at)}.` : '';
  const syncLabel = syncState.enabled ? ' Sync: enabled.' : '';
  document.getElementById('footer').innerHTML = `Database: ${escapeHtml(data.database_path)}. App totals exclude tunnel transport aggregate (${fmtBytes(data.tunnel_total_bytes)}). Observed raw total including tunnel: ${fmtBytes(data.observed_total_bytes)}.${syncLabel}${syncRetry}${err}${syncErr}`;
}
async function refreshAll() { await loadDays(); await loadSummary(); }
document.getElementById('refreshBtn').addEventListener('click', refreshAll);
datePicker.addEventListener('change', loadSummary);
previousDayBtn.addEventListener('click', () => moveRecordedDay(-1));
nextDayBtn.addEventListener('click', () => moveRecordedDay(1));
latestDayBtn.addEventListener('click', () => {
  const latest = latestRecordedDate();
  if (!latest) return;
  datePicker.value = latest;
  loadSummary().catch(err => { document.getElementById('status').textContent = err; });
});
window.addEventListener('resize', () => { loadSummary().catch(() => {}); });
refreshAll().catch(err => { document.getElementById('status').textContent = err; });
setInterval(() => { loadSummary().catch(() => {}); }, SUMMARY_REFRESH_MS);
setInterval(() => { loadDays().catch(() => {}); }, DAYS_REFRESH_MS);
</script>
</body>
</html>
"""


class DashboardServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        data_dir: Path,
        state: CollectorState,
        sync_config: SyncConfig | None,
    ):
        super().__init__(server_address, DashboardRequestHandler)
        self.data_dir = data_dir
        self.state = state
        self.sync_config = sync_config


class DashboardRequestHandler(BaseHTTPRequestHandler):
    @property
    def dashboard_server(self) -> DashboardServer:
        return cast(DashboardServer, self.server)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - inherited API name
        if os.environ.get("NETWORK_TRAFFIC_ACCESS_LOG", "").strip().lower() not in {"1", "true", "yes", "on"}:
            return
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

    def date_from_query(self, query: dict[str, list[str]]) -> str | None:
        date = first_query_value(query, "date") or day_string()
        if not is_valid_date_string(date):
            self.send_json({"error": "date must use YYYY-MM-DD"}, status=400)
            return None
        return date

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        top_limit = bounded_query_int(query, "top", DEFAULT_API_PROCESS_LIMIT, MAX_API_PROCESS_LIMIT, minimum=1)
        pid_limit = bounded_query_int(query, "pids", DEFAULT_PID_SAMPLE_LIMIT, MAX_PID_SAMPLE_LIMIT, minimum=0)
        if parsed.path == "/":
            self.send_bytes(DASHBOARD_HTML.encode("utf-8"), content_type="text/html; charset=utf-8")
            return
        if parsed.path in {"/favicon.svg", "/favicon.ico"}:
            self.send_bytes(FAVICON_SVG.encode("utf-8"), content_type="image/svg+xml; charset=utf-8")
            return
        if parsed.path == "/health":
            payload = {
                "ok": True,
                "data_dir": str(self.dashboard_server.data_dir),
                "database_path": str(database_path(self.dashboard_server.data_dir)),
                "sync": sync_status(self.dashboard_server.sync_config),
                "pid": os.getpid(),
                "collector": self.dashboard_server.state.snapshot(),
            }
            self.send_json(payload)
            return
        if parsed.path == "/api/today":
            self.send_json(
                summarize_day(
                    self.dashboard_server.data_dir,
                    top_limit=top_limit,
                    pid_limit=pid_limit,
                    sync_config=self.dashboard_server.sync_config,
                )
            )
            return
        if parsed.path == "/api/day":
            date = self.date_from_query(query)
            if date is None:
                return
            self.send_json(
                summarize_day(
                    self.dashboard_server.data_dir,
                    date,
                    top_limit=top_limit,
                    pid_limit=pid_limit,
                    sync_config=self.dashboard_server.sync_config,
                )
            )
            return
        if parsed.path == "/api/days":
            self.send_json(
                {
                    "days": list_days(self.dashboard_server.data_dir, sync_config=self.dashboard_server.sync_config),
                    "collector": self.dashboard_server.state.snapshot(),
                    "sync": sync_status(self.dashboard_server.sync_config),
                }
            )
            return
        if parsed.path == "/api/timeseries":
            date = self.date_from_query(query)
            if date is None:
                return
            self.send_json(
                {
                    "date": date,
                    "series": timeseries_day(
                        self.dashboard_server.data_dir,
                        date,
                        sync_config=self.dashboard_server.sync_config,
                    ),
                }
            )
            return
        if parsed.path == "/api/export.csv":
            date = self.date_from_query(query)
            if date is None:
                return
            self.send_bytes(
                export_csv(
                    self.dashboard_server.data_dir,
                    date,
                    include_tunnels=query_flag(query, "include_tunnels"),
                    pid_limit=pid_limit,
                    sync_config=self.dashboard_server.sync_config,
                ),
                content_type="text/csv; charset=utf-8",
            )
            return
        self.send_json({"error": "not found"}, status=404)


def first_query_value(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name) or []
    return values[0] if values else None


def is_valid_date_string(value: str) -> bool:
    try:
        parse_date(value)
    except ValueError:
        return False
    return True


def bounded_query_int(
    query: dict[str, list[str]],
    name: str,
    default: int,
    maximum: int,
    *,
    minimum: int = 0,
) -> int:
    value = first_query_value(query, name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return min(max(parsed, minimum), maximum)


def query_flag(query: dict[str, list[str]], name: str) -> bool:
    value = first_query_value(query, name)
    return bool(value and value.strip().lower() in {"1", "true", "yes", "on"})


def sync_status(sync_config: SyncConfig | None) -> dict[str, Any]:
    if not sync_config or not sync_config.enabled:
        return {"enabled": False}
    return {
        "enabled": True,
        "database_url": redacted_database_url(sync_config.database_url),
        "psql_path": sync_config.psql_path,
        "prune_after_sync": sync_config.prune_after_sync,
        "keep_local_days": sync_config.keep_local_days,
        "retry_interval_seconds": sync_config.retry_interval_seconds,
        "keychain_account": sync_config.keychain_account,
        "keychain_service": sync_config.keychain_service,
    }


def export_csv(
    data_dir: Path,
    date: str,
    *,
    include_tunnels: bool = False,
    pid_limit: int = DEFAULT_PID_SAMPLE_LIMIT,
    sync_config: SyncConfig | None = None,
) -> bytes:
    summary = summarize_day(data_dir, date, pid_limit=pid_limit, sync_config=sync_config)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "date",
        "traffic_class",
        "process",
        "bytes_in",
        "bytes_out",
        "total_bytes",
        "samples",
        "pid_count",
        "pids_sample",
    ])
    rows: list[tuple[str, dict[str, Any]]] = [("app", row) for row in summary["processes"]]
    if include_tunnels:
        rows.extend(("tunnel", row) for row in summary["tunnel_processes"])
    for traffic_class, row in rows:
        writer.writerow(
            [
                summary["date"],
                traffic_class,
                row["process"],
                row["bytes_in"],
                row["bytes_out"],
                row["total_bytes"],
                row["samples"],
                row.get("pid_count", len(row.get("pids", []))),
                " ".join(str(pid) for pid in row.get("pids", [])),
            ]
        )
    return buffer.getvalue().encode("utf-8")


def parse_bind(bind: str) -> tuple[str, int]:
    if ":" not in bind:
        raise ValueError("bind must be HOST:PORT")
    host, port_text = bind.rsplit(":", 1)
    host = host or "127.0.0.1"
    return host, int(port_text)


def attempt_sync_with_backoff(
    data_dir: Path,
    sync_config: SyncConfig | None,
    state: CollectorState,
    backoff: SyncBackoff,
    *,
    force: bool = False,
) -> list[str]:
    if not sync_config or not sync_config.enabled:
        return []
    now = local_now()
    if not force and not backoff.should_attempt(now):
        return []
    try:
        synced_days = sync_completed_days(data_dir, sync_config)
    except Exception as exc:  # noqa: BLE001 - optional archive should not stop collection
        next_attempt = backoff.record_failure(now)
        state.record_sync([], str(exc), next_attempt.isoformat(timespec="seconds"))
        return []
    backoff.record_success()
    state.record_sync(synced_days)
    return synced_days


def collector_loop(
    data_dir: Path,
    state: CollectorState,
    *,
    interval_seconds: int,
    nettop_path: str,
    stop_event: threading.Event,
    sync_config: SyncConfig | None,
    sync_backoff: SyncBackoff,
) -> None:
    while not stop_event.is_set():
        try:
            rows = collect_once(interval_seconds, nettop_path=nettop_path)
            stamp = local_now()
            append_sample_record(data_dir, rows, interval_seconds=interval_seconds, timestamp=stamp)
            state.record_sample(stamp, rows)
            if sync_config and sync_config.enabled:
                attempt_sync_with_backoff(data_dir, sync_config, state, sync_backoff)
        except Exception as exc:  # noqa: BLE001 - this is a resilient background collector
            message = str(exc)
            append_error_record(data_dir, message)
            state.record_error(message)
            stop_event.wait(min(interval_seconds, 30))


def serve(
    bind: str,
    data_dir: Path,
    *,
    interval_seconds: int,
    nettop_path: str,
    collect: bool,
    sync_config: SyncConfig | None = None,
) -> None:
    init_database(data_dir)
    state = CollectorState()
    sync_backoff = SyncBackoff(sync_config.retry_interval_seconds if sync_config else DEFAULT_SYNC_RETRY_INTERVAL_SECONDS)
    if sync_config and sync_config.enabled:
        attempt_sync_with_backoff(data_dir, sync_config, state, sync_backoff, force=True)
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
                "sync_config": sync_config,
                "sync_backoff": sync_backoff,
            },
            daemon=True,
        )
        collector.start()

    host, port = parse_bind(bind)
    server = DashboardServer((host, port), data_dir, state, sync_config)
    actual_host, actual_port = server.server_address[:2]
    print(f"Dashboard: http://{actual_host}:{actual_port}/", flush=True)
    print(f"Data dir:  {data_dir}", flush=True)
    print(f"Database:  {database_path(data_dir)}", flush=True)
    print(f"Collect:   {'on' if collect else 'off'} interval={interval_seconds}s", flush=True)
    print(f"Sync:      {'on' if sync_config and sync_config.enabled else 'off'}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...", flush=True)
    finally:
        stop_event.set()
        server.server_close()
        if collector:
            collector.join(timeout=2)


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def build_sync_config(args: argparse.Namespace) -> SyncConfig:
    database_url = args.sync_db_url or os.environ.get(SYNC_DATABASE_URL_ENV)
    psql_path = args.sync_psql or os.environ.get(SYNC_PSQL_ENV) or "psql"
    keychain_service = args.sync_keychain_service or os.environ.get(SYNC_KEYCHAIN_SERVICE_ENV)
    keychain_account = args.sync_keychain_account or os.environ.get(SYNC_KEYCHAIN_ACCOUNT_ENV)
    prune_after_sync = not args.no_sync_prune and not env_flag("NETWORK_TRAFFIC_SYNC_NO_PRUNE")
    keep_local_days = args.sync_keep_local_days
    if keep_local_days is None:
        keep_local_days = int(os.environ.get("NETWORK_TRAFFIC_SYNC_KEEP_LOCAL_DAYS", "0") or 0)
    retry_interval_seconds = args.sync_retry_interval_seconds
    if retry_interval_seconds is None:
        retry_interval_seconds = int(os.environ.get(SYNC_RETRY_INTERVAL_ENV, str(DEFAULT_SYNC_RETRY_INTERVAL_SECONDS)) or DEFAULT_SYNC_RETRY_INTERVAL_SECONDS)
    return SyncConfig(
        database_url=database_url,
        psql_path=psql_path,
        keychain_service=keychain_service,
        keychain_account=keychain_account,
        prune_after_sync=prune_after_sync,
        keep_local_days=max(0, int(keep_local_days)),
        retry_interval_seconds=max(0, int(retry_interval_seconds)),
    )


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
    parser.add_argument("--sync-db-url", help=f"optional PostgreSQL archive URL; also reads ${SYNC_DATABASE_URL_ENV}")
    parser.add_argument("--sync-psql", help=f"path to psql for optional sync; also reads ${SYNC_PSQL_ENV}")
    parser.add_argument("--sync-keychain-service", help=f"macOS Keychain service for archive DB password; also reads ${SYNC_KEYCHAIN_SERVICE_ENV}")
    parser.add_argument("--sync-keychain-account", help=f"macOS Keychain account for archive DB password; also reads ${SYNC_KEYCHAIN_ACCOUNT_ENV}")
    parser.add_argument("--sync-keep-local-days", type=int, help="completed local days to keep after sync; default 0")
    parser.add_argument("--sync-retry-interval-seconds", type=int, help=f"seconds to wait after a failed archive sync before retrying; default {DEFAULT_SYNC_RETRY_INTERVAL_SECONDS}; also reads ${SYNC_RETRY_INTERVAL_ENV}")
    parser.add_argument("--no-sync-prune", action="store_true", help="sync completed days but keep them in the local SQLite database")
    parser.add_argument("--sync-completed-days", action="store_true", help="sync and prune completed local days, then exit")
    args = parser.parse_args(argv)
    sync_config = build_sync_config(args)

    if args.interval < 1:
        parser.error("--interval must be >= 1")
    if args.sync_completed_days and not sync_config.enabled:
        parser.error("--sync-completed-days requires --sync-db-url or NETWORK_TRAFFIC_SYNC_DATABASE_URL")

    if args.init_db:
        path = init_database(args.data_dir)
        print(f"Initialized database: {path}")
        return 0

    if args.sync_completed_days:
        synced_days = sync_completed_days(args.data_dir, sync_config)
        if synced_days:
            print("Synced completed days: " + ", ".join(synced_days))
        else:
            print("No completed local days needed sync.")
        return 0

    if args.collect_once:
        rows = collect_once(args.interval, nettop_path=args.nettop)
        path = append_sample_record(args.data_dir, rows, interval_seconds=args.interval)
        if sync_config.enabled:
            sync_completed_days(args.data_dir, sync_config)
        print(f"Wrote {len(rows)} process rows to {path}")
        print_report(summarize_day(args.data_dir, sync_config=sync_config), top=args.top)
        return 0

    if args.days:
        for day in list_days(args.data_dir, sync_config=sync_config):
            print(
                f"{day['date']}  app_total={human_bytes(day['total_bytes'])}  "
                f"tunnel_excluded={human_bytes(day.get('tunnel_total_bytes', 0))}  "
                f"samples={day['sample_count']}  errors={day['error_count']}  "
                f"storage={day.get('storage', 'local')}  {day['database_path']}"
            )
        return 0

    if args.report:
        print_report(summarize_day(args.data_dir, args.report, sync_config=sync_config), top=args.top)
        return 0

    if args.serve:
        serve(
            args.serve,
            args.data_dir,
            interval_seconds=args.interval,
            nettop_path=args.nettop,
            collect=not args.no_collect,
            sync_config=sync_config,
        )
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
