# Project Context

## Project

Network Traffic Dashboard is a macOS-only local network-usage monitor. It helps identify which process is moving data when VPN clients such as Shadowrocket make Activity Monitor show most traffic under `MacPacketTunnel`.

Project path:

```text
/Users/mostafadadkhah/Documents/NetworkTrafficDashboard
```

## Operating rules

- Keep the entire project in English: UI text, comments, documentation, commit messages, and issue/PR text.
- Log important product and engineering decisions in this file.
- Keep runtime dependencies at zero unless a future decision explicitly changes that.
- Verify changes with unit tests, syntax checks, a real `nettop` sample when possible, and HTTP smoke tests for dashboard changes.

## Decision log

### 2026-07-03 - Project split

Decision: Keep this as a standalone project under `~/Documents/NetworkTrafficDashboard` instead of mixing it into the MahsaNG bridge repository.

Reason: The traffic dashboard is a general macOS diagnostic tool and should not be coupled to the subscription bridge.

### 2026-07-03 - English-only project

Decision: All project files and UI must be English.

Reason: The project is intended to be cleanly publishable on GitHub and maintainable by coding agents without mixed-language ambiguity.

### 2026-07-03 - Collector source

Decision: Use Apple's built-in `nettop` in per-process delta CSV mode:

```text
nettop -P -x -d -L 2 -s <interval> -n
```

Reason: `nettop` can still expose per-process rows even when Activity Monitor aggregates VPN traffic under a NetworkExtension packet tunnel.

### 2026-07-03 - First-sample handling

Decision: Always collect two `nettop` samples and skip the first sample block.

Reason: In delta mode, the first sample can still include cumulative counters and would distort daily totals.

### 2026-07-03 - Tunnel attribution

Decision: Mark `MacPacketTunnel`, `Shadowrocket`, and similar packet-tunnel processes as aggregate tunnel rows.

Reason: They are useful for total tunnel volume, but they are not the original app-level source when macOS can expose more specific process rows.

### 2026-07-03 - Database storage

Decision: Store all samples and per-process deltas in SQLite at:

```text
~/Library/Application Support/NetworkTrafficDashboard/network_traffic.sqlite3
```

Reason: Daily JSONL logs were useful for the first prototype, but the project now needs durable queryable storage and daily charts. SQLite provides this with no runtime dependency.

### 2026-07-03 - Dashboard implementation

Decision: Keep the dashboard zero-dependency using Python `ThreadingHTTPServer`, JSON APIs, and browser-native canvas charts.

Reason: The tool should be easy to run as a local utility without package managers, bundlers, or web framework setup.

### 2026-07-03 - Charts

Decision: Provide three dashboard charts: daily totals across recorded days, hourly traffic for the selected day, and top processes for the selected day.

Reason: This covers both high-level daily trend analysis and drill-down into the selected day.

### 2026-07-03 - Autolaunch

Decision: Use a user LaunchAgent named `com.mostafa.network-traffic-dashboard` with `RunAtLoad` and `KeepAlive`.

Reason: It starts automatically at login without requiring root privileges and is the native macOS mechanism for a persistent user-level collector.

### 2026-07-03 - GitHub visibility

Decision: Create the GitHub repository as private by default, then switch visibility only after an explicit user decision.

Reason: The project contains no intended sensitive data, but private is the safer default for a local diagnostics tool until publication is explicitly requested.

### 2026-07-04 - Public GitHub repository

Decision: Change the GitHub repository visibility to public after explicit user direction.

Reason: The user wants the macOS dashboard project to be publicly accessible. A tracked-file scan found no credentials or large private artifacts before publishing.

### 2026-07-03 - App-attributed totals exclude tunnel aggregates

Decision: The main dashboard totals, charts, process table, and CLI reports must exclude `MacPacketTunnel` / `Shadowrocket` tunnel aggregate rows by default. The excluded tunnel transport volume remains visible in separate `tunnel_*` fields and a dedicated dashboard card.

Reason: Ranking `MacPacketTunnel` as the top process answers the wrong question. The user needs the best macOS-exposed app attribution before traffic enters Shadowrocket or another tunnel. Tunnel aggregate rows are transport/overhead evidence, not the real app ranking.

### 2026-07-03 - Calendar-style date navigation

Decision: Use a browser-native `input type="date"` control plus previous/next/latest recorded-day buttons instead of a plain select dropdown.

Reason: Daily review is the core dashboard workflow, and a calendar-style picker makes it faster to jump between dates while preserving the zero-dependency dashboard implementation.

### 2026-07-04 - Built-in SVG favicon

Decision: Serve a high-contrast inline SVG favicon from `/favicon.svg` and link it from the dashboard HTML instead of adding an external asset pipeline.

Reason: The favicon should make the dashboard easy to find among browser tabs while keeping the zero-runtime-dependency, single-file dashboard architecture.

### 2026-07-04 - Readable chart axis labels

Decision: Render vertical bar-chart x-axis labels horizontally below the plot area, shorten daily labels to `MM/DD`, and skip labels automatically when the chart is dense.

Reason: Rotated date labels can overlap bars and make the dashboard harder to scan. The chart should preserve clear plot/axis separation without adding a charting dependency.
