#!/usr/bin/env bash
# Resolve tracer args from env vars and exec tracer.py.
#
# Required env: FN_VA (e.g. 0x000EF6D8).
# Optional: SELF_PTR, FLAGS, XY_PACKED, BTN, RECORDING_ID, TRACE_NAME.
#
# If RECORDING_ID is set and SELF_PTR/XY_PACKED are not provided, we attempt
# to derive xy from the first input_mouse_button "down" event in the recording.

set -euo pipefail

PE_PATH="${PE_PATH:-/game/DXRender.exe}"
FN_VA="${FN_VA:-0x000EF6D8}"
SELF_PTR="${SELF_PTR:-0x00206784}"   # default: VA_ACTIVE_WIDGET (PTR slot)
FLAGS="${FLAGS:-0x08}"               # 0x08 = mouse-down
BTN="${BTN:-1}"                      # 1 = LMB
TRACE_NAME="${TRACE_NAME:-trace}"
MAX_INSTRS="${MAX_INSTRS:-1000000}"
TIMEOUT_S="${TIMEOUT_S:-10}"

# Derive XY_PACKED from a recording if not provided.
if [[ -z "${XY_PACKED:-}" ]]; then
    if [[ -n "${RECORDING_ID:-}" && -f "/sessions/recording_${RECORDING_ID}.jsonl" ]]; then
        # Pull the first "down" event, take fx/fy * cw/ch and pack as (X<<16)|Y.
        read -r XY_PACKED < <(python3 - "/sessions/recording_${RECORDING_ID}.jsonl" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as f:
    for line in f:
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get("kind") == "input_mouse_button" and ev.get("state") == "down":
            x = int(round(ev["fx"] * ev["cw"]))
            y = int(round(ev["fy"] * ev["ch"]))
            print(hex(((x & 0xFFFF) << 16) | (y & 0xFFFF)))
            break
    else:
        print("0x00640032")
PY
)
    else
        XY_PACKED="0x00640032"   # default: x=100, y=50
    fi
fi

mkdir -p /traces
OUT="/traces/${TRACE_NAME}.jsonl"

echo "[entrypoint] tracing PE=${PE_PATH} fn=${FN_VA} self=${SELF_PTR} flags=${FLAGS} xy=${XY_PACKED} btn=${BTN}"
echo "[entrypoint] out=${OUT}"

exec python3 /app/tracer.py \
    --pe "${PE_PATH}" \
    --fn-va "${FN_VA}" \
    --self-ptr "${SELF_PTR}" \
    --flags "${FLAGS}" \
    --xy-packed "${XY_PACKED}" \
    --btn "${BTN}" \
    --max-instrs "${MAX_INSTRS}" \
    --timeout-s "${TIMEOUT_S}" \
    --out "${OUT}"
