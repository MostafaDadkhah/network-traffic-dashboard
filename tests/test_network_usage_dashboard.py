#!/usr/bin/env python3
"""Tests for the macOS network usage dashboard."""

from __future__ import annotations

import contextlib
import io
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone

import network_usage_dashboard as dashboard


NETTOP_CSV = """time,,interface,state,bytes_in,bytes_out,rx_dupe,rx_ooo,re-tx,rtt_avg,rcvsize,tx_win,tc_class,tc_mgt,cc_algo,P,C,R,W,arch,
20:48:16.223325,io.tailscale.ip.79391,,,3950703,10739706,14139,614,71703,,,,,,,,,,,,
20:48:16.223341,MacPacketTunnel.18262,,,146969880,145968400,30211,5822907,83618,,,,,,,,,,,,
time,,interface,state,bytes_in,bytes_out,rx_dupe,rx_ooo,re-tx,rtt_avg,rcvsize,tx_win,tc_class,tc_mgt,cc_algo,P,C,R,W,arch,
20:48:17.212278,io.tailscale.ip.79391,,,745,952,0,0,0,,,,,,,,,,,,
20:48:17.212294,MacPacketTunnel.18262,,,39652,1085,0,0,24,,,,,,,,,,,,
20:48:17.212295,Code Helper (Pl.51458,,,0,702,0,0,0,,,,,,,,,,,,
"""


def test_parse_nettop_csv_skips_first_cumulative_sample() -> None:
    rows = dashboard.parse_nettop_csv(NETTOP_CSV)

    assert [row.raw_process for row in rows] == [
        "io.tailscale.ip.79391",
        "MacPacketTunnel.18262",
        "Code Helper (Pl.51458",
    ]
    assert rows[0].process == "io.tailscale.ip"
    assert rows[0].pid == 79391
    assert rows[0].bytes_in == 745
    assert rows[0].bytes_out == 952
    assert rows[1].process == "MacPacketTunnel"
    assert rows[1].pid == 18262
    assert dashboard.is_tunnel_process(rows[1].process)


def test_append_and_summarize_daily_database(tmp_path) -> None:
    rows = dashboard.parse_nettop_csv(NETTOP_CSV)
    timestamp = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)

    db_path = dashboard.append_sample_record(tmp_path, rows, interval_seconds=1, timestamp=timestamp)
    summary = dashboard.summarize_day(tmp_path, "2026-07-03")

    assert db_path.name == dashboard.DATABASE_FILENAME
    assert db_path.exists()
    assert summary["sample_count"] == 1
    assert summary["error_count"] == 0
    app_total = rows[0].total_bytes + rows[2].total_bytes
    tunnel_total = rows[1].total_bytes
    assert summary["total_bytes"] == app_total
    assert summary["tunnel_total_bytes"] == tunnel_total
    assert summary["observed_total_bytes"] == app_total + tunnel_total
    assert summary["processes"][0]["process"] == "io.tailscale.ip"
    assert summary["processes"][0]["pid_count"] == 1
    assert not summary["processes"][0]["pids_truncated"]
    assert all(not row["is_tunnel"] for row in summary["processes"])
    assert summary["tunnel_processes"][0]["process"] == "MacPacketTunnel"
    assert summary["latest_processes"][0]["process"] == "io.tailscale.ip"
    assert summary["latest_processes"][0]["samples"] == 1
    assert summary["latest_tunnel_processes"][0]["process"] == "MacPacketTunnel"

    days = dashboard.list_days(tmp_path)
    assert days[0]["date"] == "2026-07-03"
    assert days[0]["total_bytes"] == summary["total_bytes"]
    assert days[0]["tunnel_total_bytes"] == summary["tunnel_total_bytes"]


def test_timeseries_groups_samples_by_hour(tmp_path) -> None:
    rows = [dashboard.ProcessDelta("node.123", "node", 123, 100, 50)]
    dashboard.append_sample_record(
        tmp_path,
        rows,
        interval_seconds=1,
        timestamp=datetime(2026, 7, 3, 12, 1, 0, tzinfo=timezone.utc),
    )
    dashboard.append_sample_record(
        tmp_path,
        rows,
        interval_seconds=1,
        timestamp=datetime(2026, 7, 3, 12, 2, 0, tzinfo=timezone.utc),
    )

    series = dashboard.timeseries_day(tmp_path, "2026-07-03")

    assert series == [
        {
            "hour": "12",
            "bytes_in": 200,
            "bytes_out": 100,
            "total_bytes": 300,
            "tunnel_total_bytes": 0,
            "observed_total_bytes": 300,
            "sample_count": 2,
            "label": "12:00",
        }
    ]


def test_export_csv_contains_process_totals(tmp_path) -> None:
    rows = [
        dashboard.ProcessDelta("node.123", "node", 123, 100, 50),
        dashboard.ProcessDelta("node.456", "node", 456, 10, 40),
    ]
    timestamp = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)
    dashboard.append_sample_record(tmp_path, rows, interval_seconds=1, timestamp=timestamp)

    csv_bytes = dashboard.export_csv(tmp_path, "2026-07-03")
    csv_text = csv_bytes.decode("utf-8")

    assert "date,traffic_class,process,bytes_in,bytes_out,total_bytes,samples,pid_count,pids_sample" in csv_text
    assert "2026-07-03,app,node,110,90,200,2,2," in csv_text


def test_export_csv_can_include_tunnel_rows(tmp_path) -> None:
    rows = [
        dashboard.ProcessDelta("node.123", "node", 123, 100, 50),
        dashboard.ProcessDelta("MacPacketTunnel.456", "MacPacketTunnel", 456, 10, 40),
    ]
    timestamp = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)
    dashboard.append_sample_record(tmp_path, rows, interval_seconds=1, timestamp=timestamp)

    default_csv = dashboard.export_csv(tmp_path, "2026-07-03").decode("utf-8")
    tunnel_csv = dashboard.export_csv(tmp_path, "2026-07-03", include_tunnels=True).decode("utf-8")

    assert "MacPacketTunnel" not in default_csv
    assert "2026-07-03,tunnel,MacPacketTunnel,10,40,50,1,1,456" in tunnel_csv


def test_summary_caps_pid_lists_but_reports_pid_count(tmp_path) -> None:
    timestamp = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)
    for offset in range(12):
        dashboard.append_sample_record(
            tmp_path,
            [dashboard.ProcessDelta(f"node.{100 + offset}", "node", 100 + offset, 1, 1)],
            interval_seconds=1,
            timestamp=timestamp,
        )

    summary = dashboard.summarize_day(tmp_path, "2026-07-03", pid_limit=3)
    row = summary["processes"][0]

    assert row["pid_count"] == 12
    assert row["pids_truncated"] is True
    assert row["pids"] == [111, 110, 109]


def test_http_invalid_date_returns_400_and_access_log_is_silent_by_default(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("NETWORK_TRAFFIC_ACCESS_LOG", raising=False)
    dashboard.init_database(tmp_path)
    state = dashboard.CollectorState()
    server = dashboard.DashboardServer(("127.0.0.1", 0), tmp_path, state, None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    stderr = io.StringIO()
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/api/day?date=not-a-date"

    try:
        with contextlib.redirect_stderr(stderr):
            try:
                urllib.request.urlopen(url, timeout=5)
            except urllib.error.HTTPError as exc:
                assert exc.code == 400
                assert b"date must use YYYY-MM-DD" in exc.read()
            else:  # pragma: no cover - defensive assertion clarity
                raise AssertionError("invalid date request unexpectedly succeeded")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert stderr.getvalue() == ""


def test_completed_local_days_respects_today_and_keep_window(tmp_path) -> None:
    rows = [dashboard.ProcessDelta("node.123", "node", 123, 100, 50)]
    dashboard.append_sample_record(
        tmp_path,
        rows,
        interval_seconds=1,
        timestamp=datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc),
    )
    dashboard.append_sample_record(
        tmp_path,
        rows,
        interval_seconds=1,
        timestamp=datetime(2026, 7, 4, 0, 1, 0, tzinfo=timezone.utc),
    )

    sync_config = dashboard.SyncConfig(database_url="postgresql://user@example.test/archive")
    assert dashboard.completed_local_days(tmp_path, sync_config, today="2026-07-04") == ["2026-07-03"]

    keep_yesterday = dashboard.SyncConfig(
        database_url="postgresql://user@example.test/archive",
        keep_local_days=1,
    )
    assert dashboard.completed_local_days(tmp_path, keep_yesterday, today="2026-07-04") == []


def test_delete_local_day_only_removes_selected_day(tmp_path) -> None:
    rows = [dashboard.ProcessDelta("node.123", "node", 123, 100, 50)]
    dashboard.append_sample_record(
        tmp_path,
        rows,
        interval_seconds=1,
        timestamp=datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc),
    )
    dashboard.append_sample_record(
        tmp_path,
        rows,
        interval_seconds=1,
        timestamp=datetime(2026, 7, 4, 12, 0, 0, tzinfo=timezone.utc),
    )

    dashboard.delete_local_day(tmp_path, "2026-07-03", vacuum=False)

    assert dashboard.summarize_day(tmp_path, "2026-07-03")["sample_count"] == 0
    assert dashboard.summarize_day(tmp_path, "2026-07-04")["sample_count"] == 1


def test_postgres_env_and_redaction_do_not_expose_password() -> None:
    sync_config = dashboard.SyncConfig(
        database_url="postgresql://user:secret@example.test:5433/archive?sslmode=require&application_name=ntd"
    )

    env = dashboard.postgres_env(sync_config)

    assert env["PGHOST"] == "example.test"
    assert env["PGPORT"] == "5433"
    assert env["PGDATABASE"] == "archive"
    assert env["PGUSER"] == "user"
    assert env["PGPASSWORD"] == "secret"
    assert env["PGSSLMODE"] == "require"
    assert env["PGAPPNAME"] == "ntd"
    assert "secret" not in dashboard.redacted_database_url(sync_config.database_url)


def test_dashboard_html_is_english() -> None:
    assert '<html lang="en"' in dashboard.DASHBOARD_HTML
    assert "Network Traffic Dashboard" in dashboard.DASHBOARD_HTML
    assert 'rel="icon" type="image/svg+xml" href="/favicon.svg"' in dashboard.DASHBOARD_HTML
    assert "Pre-tunnel app-attributed traffic" in dashboard.DASHBOARD_HTML
    assert 'id="datePicker" type="date"' in dashboard.DASHBOARD_HTML
    assert "Previous day" in dashboard.DASHBOARD_HTML
    assert "Next day" in dashboard.DASHBOARD_HTML
    assert "Latest day" in dashboard.DASHBOARD_HTML
    assert "formatDateLabel" in dashboard.DASHBOARD_HTML
    assert "labelMinWidth" in dashboard.DASHBOARD_HTML
    assert "lastLabelIndex" in dashboard.DASHBOARD_HTML
    assert "chartTooltip" in dashboard.DASHBOARD_HTML
    assert "DASHBOARD_TOP_LIMIT" in dashboard.DASHBOARD_HTML
    assert "PID_SAMPLE_LIMIT" in dashboard.DASHBOARD_HTML
    assert "formatPids" in dashboard.DASHBOARD_HTML
    assert "PID sample" in dashboard.DASHBOARD_HTML
    assert "tooltipHtml" in dashboard.DASHBOARD_HTML
    assert "Download" in dashboard.DASHBOARD_HTML
    assert "Upload" in dashboard.DASHBOARD_HTML
    assert "ctx.rotate" not in dashboard.DASHBOARD_HTML
    assert "daySelect" not in dashboard.DASHBOARD_HTML
    assert "No data has been recorded yet." in dashboard.DASHBOARD_HTML


def test_favicon_svg_is_browser_visible() -> None:
    assert dashboard.FAVICON_SVG.startswith('<svg xmlns="http://www.w3.org/2000/svg"')
    assert 'viewBox="0 0 64 64"' in dashboard.FAVICON_SVG
    assert "#22c55e" in dashboard.FAVICON_SVG
    assert "#38bdf8" in dashboard.FAVICON_SVG
