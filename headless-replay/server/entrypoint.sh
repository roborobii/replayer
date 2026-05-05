#!/usr/bin/env bash
set -euo pipefail

SESSIONS_DIR="${SESSIONS_DIR:-/sessions}"
REWRITE_HOST="${REWRITE_HOST:-10.42.0.10}"
SPEED="${SPEED:-1.0}"

if [[ -n "${RECORDING_ID:-}" ]]; then
  JSONL="${SESSIONS_DIR}/recording_${RECORDING_ID}.jsonl"
  if [[ ! -f "${JSONL}" ]]; then
    echo "ERROR: Recording not found: ${JSONL}" >&2
    exit 1
  fi
else
  JSONL="$(ls -t "${SESSIONS_DIR}"/recording_*.jsonl 2>/dev/null | head -n1 || true)"
  if [[ -z "${JSONL}" || ! -f "${JSONL}" ]]; then
    echo "ERROR: No recording_*.jsonl files found in ${SESSIONS_DIR}" >&2
    exit 1
  fi
fi

echo "[entrypoint] Using recording: ${JSONL}"
echo "[entrypoint] Bind: 0.0.0.0  Rewrite-host: ${REWRITE_HOST}  Speed: ${SPEED}"

ARGS=(
  "${JSONL}"
  --bind 0.0.0.0
  --rewrite-host "${REWRITE_HOST}"
  --speed "${SPEED}"
  --world-lookahead-seq 999999
  --world-gate-timeout-s 0.5
)

if [[ -n "${SWAP_WITH_CHARACTER:-}" ]]; then
  ARGS+=(--swap-with-character "${SWAP_WITH_CHARACTER}")
  echo "[entrypoint] Swap-with-character: ${SWAP_WITH_CHARACTER}"
fi

exec python3 -u /app/v2_server.py "${ARGS[@]}"
