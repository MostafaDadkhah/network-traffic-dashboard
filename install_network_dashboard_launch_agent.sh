#!/bin/zsh
set -euo pipefail

LABEL="com.mostafa.network-traffic-dashboard"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/usr/local/bin/python3}"
BIND="${BIND:-127.0.0.1:18686}"
INTERVAL="${INTERVAL:-60}"
DATA_DIR="${DATA_DIR:-$HOME/Library/Application Support/NetworkTrafficDashboard}"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_DIR="$HOME/Library/Logs/NetworkTrafficDashboard"

if [[ ! -x "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  else
    echo "Python 3 not found. Install Python 3.10+ and retry." >&2
    exit 1
  fi
fi

if ! command -v nettop >/dev/null 2>&1; then
  echo "nettop not found; this tool is macOS-only." >&2
  exit 1
fi

"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10+ is required for network_usage_dashboard.py")
PY

mkdir -p "$HOME/Library/LaunchAgents" "$LOG_DIR" "$DATA_DIR"

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYTHON_BIN</string>
    <string>$PROJECT_DIR/network_usage_dashboard.py</string>
    <string>--serve</string>
    <string>$BIND</string>
    <string>--interval</string>
    <string>$INTERVAL</string>
    <string>--data-dir</string>
    <string>$DATA_DIR</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$PROJECT_DIR</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$LOG_DIR/stdout.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/stderr.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PYTHONUNBUFFERED</key>
    <string>1</string>
  </dict>
</dict>
</plist>
PLIST

UID_NUM="$(id -u)"
launchctl bootout "gui/$UID_NUM" "$PLIST" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$UID_NUM" "$PLIST"
launchctl kickstart -k "gui/$UID_NUM/$LABEL"

echo "Installed and started $LABEL"
echo "Dashboard: http://$BIND/"
echo "Database: $DATA_DIR/network_traffic.sqlite3"
echo "Service logs: $LOG_DIR"
echo "Plist: $PLIST"
