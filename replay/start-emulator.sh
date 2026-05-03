#!/usr/bin/env bash
# start-emulator.sh — stop any prior v2_server.py, start a fresh one.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
RECORDING="${1:-$ROOT/sessions/recording_smoke5.jsonl}"
BIND="${BIND:-0.0.0.0}"
LOG="/tmp/v2_server.log"

if [[ ! -f "$RECORDING" ]]; then
  echo "recording not found: $RECORDING" >&2
  exit 2
fi

# Kill any prior instance.
PRIOR_PIDS="$(pgrep -f "v2_server.py" || true)"
if [[ -n "$PRIOR_PIDS" ]]; then
  echo "stopping prior v2_server.py: $PRIOR_PIDS"
  kill $PRIOR_PIDS 2>/dev/null || true
  sleep 0.5
  kill -9 $PRIOR_PIDS 2>/dev/null || true
fi

: > "$LOG"
nohup python3 "$HERE/v2_server.py" "$RECORDING" --bind "$BIND" >>"$LOG" 2>&1 &
PID=$!
disown "$PID" || true

sleep 0.3
echo "v2_server.py pid=$PID bind=$BIND recording=$RECORDING"
echo "log: $LOG"
echo "stop: kill $PID"
