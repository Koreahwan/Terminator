#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PID_DIR="$ROOT_DIR/.pids"
PID_FILE="$PID_DIR/overview_server.pid"
LOG_FILE="$PID_DIR/overview_server.log"
HOST="${OVERVIEW_HOST:-127.0.0.1}"
PORT="${OVERVIEW_PORT:-8450}"
HEALTH_URL="http://${HOST}:${PORT}/OVERVIEW.html"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

probe_dashboard() {
  local body

  if ! body="$(curl --silent --show-error --fail --max-time 5 "$HEALTH_URL" 2>/dev/null)"; then
    return 1
  fi

  grep -q "Terminator — Project Overview" <<<"$body"
}

read_pid() {
  if [ ! -f "$PID_FILE" ]; then
    return 1
  fi

  tr -d '[:space:]' < "$PID_FILE"
}

cleanup_stale_pid() {
  local pid

  if ! pid="$(read_pid)"; then
    return 0
  fi

  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$PID_FILE"
  fi
}

start_dashboard() {
  mkdir -p "$PID_DIR"
  cd "$ROOT_DIR"

  nohup python3 "$ROOT_DIR/docs/overview_server.py" >"$LOG_FILE" 2>&1 &
  echo "$!" > "$PID_FILE"
}

wait_until_ready() {
  local _i

  for _i in $(seq 1 20); do
    if probe_dashboard; then
      return 0
    fi
    sleep 0.5
  done

  return 1
}

main() {
  require_cmd python3
  require_cmd curl
  require_cmd nohup

  if probe_dashboard; then
    echo "Dashboard already running at http://${HOST}:${PORT}/"
    exit 0
  fi

  cleanup_stale_pid

  if [ -f "$PID_FILE" ]; then
    echo "Dashboard process already exists; waiting for readiness..."
  else
    start_dashboard
  fi

  if wait_until_ready; then
    echo "Dashboard ready at http://${HOST}:${PORT}/"
    exit 0
  fi

  echo "Dashboard failed to start. Check $LOG_FILE" >&2
  exit 1
}

main "$@"
