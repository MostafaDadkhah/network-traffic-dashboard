# Codex Guide

This file is the operating guide for coding agents working on Network Traffic Dashboard.

## Mission

Build and maintain a macOS local network-usage dashboard that records every collector sample in SQLite and helps the user identify high-traffic processes when VPN/Shadowrocket traffic is hard to attribute in Activity Monitor.

## Non-negotiables

1. Keep the project English-only: UI text, code comments, documentation, commit messages, issue text, and release text.
2. Read `context.md` before making product or architecture changes.
3. Append important decisions to the `context.md` decision log immediately.
4. Do not add runtime dependencies unless there is a documented decision in `context.md`.
5. Do not commit generated databases, caches, logs, or local service artifacts.
6. Verify with real commands before claiming success.

## Key files

- `network_usage_dashboard.py`: collector, SQLite storage, HTTP API, and dashboard HTML.
- `install_network_dashboard_launch_agent.sh`: installs and starts the user LaunchAgent.
- `uninstall_network_dashboard_launch_agent.sh`: removes the LaunchAgent and keeps collected data.
- `tests/test_network_usage_dashboard.py`: parser, SQLite aggregation, timeseries, CSV, and UI language tests.
- `context.md`: project context and decision log.
- `README.md`: user-facing documentation.

## Data model

Default database:

```text
~/Library/Application Support/NetworkTrafficDashboard/network_traffic.sqlite3
```

Tables:

- `metadata`: schema metadata.
- `samples`: one row per collector sample.
- `process_deltas`: one row per process inside a sample.
- `errors`: collector errors.

## Collector behavior

Use:

```text
nettop -P -x -d -L 2 -s <interval> -n
```

Rules:

- Skip the first sample block because it may contain cumulative counters.
- Parse process identity with `rpartition('.')` because names such as `io.tailscale.ip.79391` contain dots.
- Tag `MacPacketTunnel`, `Shadowrocket`, and similar tunnel processes as aggregate tunnel rows.
- Do not rank tunnel aggregates as app usage. Main totals, charts, and tables should use app-attributed non-tunnel rows by default and expose tunnel aggregate volume separately.
- Do not return unbounded PID lists from summary APIs. Return `pid_count` plus a small recent PID sample so respawning processes remain visible without bloating JSON or breaking the table.
- Keep dashboard access logging off by default; enable `NETWORK_TRAFFIC_ACCESS_LOG=1` only for request-level debugging.

## Verification commands

Run from the project root:

```bash
python3 -m py_compile network_usage_dashboard.py tests/test_network_usage_dashboard.py
python3 -m pytest -q
```

Real collector smoke:

```bash
tmpdir="$(mktemp -d)"
python3 network_usage_dashboard.py --collect-once --interval 1 --data-dir "$tmpdir"
python3 network_usage_dashboard.py --report --data-dir "$tmpdir" --top 5
```

HTTP smoke:

1. Start the server with a temporary data dir and `--no-collect` if a sample already exists.
2. Request `/health`, `/api/today`, `/api/days`, `/api/timeseries`, `/favicon.svg`, and `/`.
3. Verify the HTML contains `Network Traffic Dashboard` and links the built-in SVG favicon.

## LaunchAgent notes

Label:

```text
com.mostafa.network-traffic-dashboard
```

Service logs:

```text
~/Library/Logs/NetworkTrafficDashboard/stdout.log
~/Library/Logs/NetworkTrafficDashboard/stderr.log
```

If port `127.0.0.1:18686` is already in use, stop the manual server before installing or restarting the LaunchAgent.
