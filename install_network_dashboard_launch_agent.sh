#!/bin/zsh
set -euo pipefail

LABEL="com.mostafa.network-traffic-dashboard"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/usr/local/bin/python3}"
BIND="${BIND:-127.0.0.1:18686}"
INTERVAL="${INTERVAL:-60}"
DATA_DIR="${DATA_DIR:-$HOME/Library/Application Support/NetworkTrafficDashboard}"
SYNC_DB_URL="${SYNC_DB_URL:-${NETWORK_TRAFFIC_SYNC_DATABASE_URL:-}}"
SYNC_PSQL="${SYNC_PSQL:-${NETWORK_TRAFFIC_SYNC_PSQL:-psql}}"
SYNC_KEYCHAIN_SERVICE="${SYNC_KEYCHAIN_SERVICE:-${NETWORK_TRAFFIC_SYNC_KEYCHAIN_SERVICE:-}}"
SYNC_KEYCHAIN_ACCOUNT="${SYNC_KEYCHAIN_ACCOUNT:-${NETWORK_TRAFFIC_SYNC_KEYCHAIN_ACCOUNT:-}}"
SYNC_KEEP_LOCAL_DAYS="${SYNC_KEEP_LOCAL_DAYS:-${NETWORK_TRAFFIC_SYNC_KEEP_LOCAL_DAYS:-0}}"
SYNC_NO_PRUNE="${SYNC_NO_PRUNE:-${NETWORK_TRAFFIC_SYNC_NO_PRUNE:-}}"
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

PROGRAM_ARGS=(
  "$PYTHON_BIN"
  "$PROJECT_DIR/network_usage_dashboard.py"
  "--serve"
  "$BIND"
  "--interval"
  "$INTERVAL"
  "--data-dir"
  "$DATA_DIR"
)

if [[ -n "$SYNC_DB_URL" ]]; then
  PROGRAM_ARGS+=("--sync-db-url" "$SYNC_DB_URL" "--sync-psql" "$SYNC_PSQL" "--sync-keep-local-days" "$SYNC_KEEP_LOCAL_DAYS")
  if [[ -n "$SYNC_KEYCHAIN_SERVICE" ]]; then
    PROGRAM_ARGS+=("--sync-keychain-service" "$SYNC_KEYCHAIN_SERVICE")
  fi
  if [[ -n "$SYNC_KEYCHAIN_ACCOUNT" ]]; then
    PROGRAM_ARGS+=("--sync-keychain-account" "$SYNC_KEYCHAIN_ACCOUNT")
  fi
  if [[ -n "$SYNC_NO_PRUNE" ]]; then
    PROGRAM_ARGS+=("--no-sync-prune")
  fi
fi

PROGRAM_ARGS_JSON="$("$PYTHON_BIN" -c 'import json, sys; print(json.dumps(sys.argv[1:]))' "${PROGRAM_ARGS[@]}")"
export LABEL PROJECT_DIR LOG_DIR PROGRAM_ARGS_JSON
"$PYTHON_BIN" - "$PLIST" <<'PY'
import json
import os
import plistlib
import sys

plist_path = sys.argv[1]
payload = {
    "Label": os.environ["LABEL"],
    "ProgramArguments": json.loads(os.environ["PROGRAM_ARGS_JSON"]),
    "WorkingDirectory": os.environ["PROJECT_DIR"],
    "RunAtLoad": True,
    "KeepAlive": True,
    "StandardOutPath": os.path.join(os.environ["LOG_DIR"], "stdout.log"),
    "StandardErrorPath": os.path.join(os.environ["LOG_DIR"], "stderr.log"),
    "EnvironmentVariables": {"PYTHONUNBUFFERED": "1"},
}
with open(plist_path, "wb") as handle:
    plistlib.dump(payload, handle, sort_keys=False)
PY

UID_NUM="$(id -u)"
launchctl bootout "gui/$UID_NUM" "$PLIST" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$UID_NUM" "$PLIST"
launchctl kickstart -k "gui/$UID_NUM/$LABEL"

echo "Installed and started $LABEL"
echo "Dashboard: http://$BIND/"
echo "Database: $DATA_DIR/network_traffic.sqlite3"
if [[ -n "$SYNC_DB_URL" ]]; then
  echo "Sync: enabled"
else
  echo "Sync: disabled"
fi
echo "Service logs: $LOG_DIR"
echo "Plist: $PLIST"
