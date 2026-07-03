#!/usr/bin/env python3
"""Tests for the macOS network usage dashboard."""

from __future__ import annotations

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
    assert summary["total_bytes"] == sum(row.total_bytes for row in rows)
    assert summary["processes"][0]["process"] == "MacPacketTunnel"
    assert summary["processes"][0]["is_tunnel"] is True
    assert summary["latest_processes"][0]["process"] == "MacPacketTunnel"

    days = dashboard.list_days(tmp_path)
    assert days[0]["date"] == "2026-07-03"
    assert days[0]["total_bytes"] == summary["total_bytes"]


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

    assert "process,bytes_in,bytes_out,total_bytes" in csv_text
    assert "node,110,90,200" in csv_text


def test_dashboard_html_is_english() -> None:
    assert '<html lang="en"' in dashboard.DASHBOARD_HTML
    assert "Network Traffic Dashboard" in dashboard.DASHBOARD_HTML
    assert "No data has been recorded yet." in dashboard.DASHBOARD_HTML
