#!/bin/zsh
set -euo pipefail

LABEL="com.mostafa.network-traffic-dashboard"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
UID_NUM="$(id -u)"

launchctl bootout "gui/$UID_NUM" "$PLIST" >/dev/null 2>&1 || true
rm -f "$PLIST"

echo "Uninstalled $LABEL"
echo "Collected database was kept under: $HOME/Library/Application Support/NetworkTrafficDashboard/network_traffic.sqlite3"
