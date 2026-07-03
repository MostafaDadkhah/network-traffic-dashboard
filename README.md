# Network Traffic Dashboard

A macOS-only, zero-runtime-dependency network traffic dashboard for figuring out which process is moving data when VPN clients such as Shadowrocket aggregate traffic under `MacPacketTunnel` in Activity Monitor.

The collector samples Apple's `nettop`, stores every sample in SQLite, and serves a local dashboard with daily, hourly, and per-process charts. The main dashboard view reports app-attributed traffic before the tunnel and keeps tunnel transport aggregates separate so `MacPacketTunnel` does not hide the real app ranking.

## Features

- Per-process traffic attribution using `nettop -P -x -d -L 2 -s <interval> -n`.
- SQLite database storage for every sample and every process delta.
- Daily app-attributed totals chart across all recorded days.
- Hourly app-attributed chart for the selected day.
- Top app-process chart and table for the selected day.
- Separate tunnel aggregate card for `MacPacketTunnel` / `Shadowrocket` transport volume.
- CSV export for each day.
- macOS LaunchAgent installer for automatic background collection.
- No runtime Python packages beyond the standard library.

## Run manually

```bash
cd ~/Documents/NetworkTrafficDashboard
python3 network_usage_dashboard.py --serve 127.0.0.1:18686 --interval 60
```

Open:

```text
http://127.0.0.1:18686/
```

## Data storage

Default data directory:

```text
~/Library/Application Support/NetworkTrafficDashboard
```

Default SQLite database:

```text
~/Library/Application Support/NetworkTrafficDashboard/network_traffic.sqlite3
```

The database stores:

- `samples`: one row per collector sample.
- `process_deltas`: one row per process observed in each sample.
- `errors`: collector errors, if any.
- `metadata`: schema version and future metadata.

## Install as a macOS LaunchAgent

```bash
cd ~/Documents/NetworkTrafficDashboard
./install_network_dashboard_launch_agent.sh
```

Defaults:

- Dashboard: `http://127.0.0.1:18686/`
- Sample interval: `60` seconds
- Database: `~/Library/Application Support/NetworkTrafficDashboard/network_traffic.sqlite3`
- Service logs: `~/Library/Logs/NetworkTrafficDashboard/`

Override examples:

```bash
INTERVAL=30 BIND=127.0.0.1:18687 ./install_network_dashboard_launch_agent.sh
```

## Uninstall LaunchAgent

```bash
cd ~/Documents/NetworkTrafficDashboard
./uninstall_network_dashboard_launch_agent.sh
```

Collected database files are kept.

## CLI reports

Initialize the database:

```bash
python3 network_usage_dashboard.py --init-db
```

Take one sample and save it:

```bash
python3 network_usage_dashboard.py --collect-once --interval 3
```

Show reports:

```bash
python3 network_usage_dashboard.py --report
python3 network_usage_dashboard.py --days
```

CSV export is available from the dashboard:

```text
/api/export.csv?date=YYYY-MM-DD
```

## Local API

- `GET /health`
- `GET /api/today`
- `GET /api/day?date=YYYY-MM-DD`
- `GET /api/days`
- `GET /api/timeseries?date=YYYY-MM-DD`
- `GET /api/export.csv?date=YYYY-MM-DD`

## Development

```bash
cd ~/Documents/NetworkTrafficDashboard
python3 -m pip install -r requirements-dev.txt
python3 -m py_compile network_usage_dashboard.py tests/test_network_usage_dashboard.py
python3 -m pytest -q
```

## Notes

`MacPacketTunnel` and `Shadowrocket` rows are aggregate tunnel transport usage, not the real app ranking. The dashboard excludes those tunnel rows from main totals, charts, tables, and CLI reports by default, then shows the excluded tunnel volume separately. Other rows such as `Chrome`, `node`, `Python`, `Telegram`, or `Tailscale` identify processes macOS can still attribute before traffic enters the tunnel. Attribution is useful, but not perfect: traffic that macOS only exposes as packet-tunnel transport cannot be reassigned to an original app without deeper privileged packet/flow instrumentation.
