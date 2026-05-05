#!/usr/bin/env bash
# Headless wine-client orchestrator.
# 1) Xvfb on :99 (1440x975 to match recording native).
# 2) Wineprefix init + Direct3D GL compat regkeys (matches wine-replay's
#    `gl-compat` Makefile target — needed for D3D8/9 under llvmpipe).
# 3) Wait for replay-server (10.42.0.10:1818) to accept connections.
# 4) Resolve recording (RECORDING_ID env wins, else newest by mtime).
# 5) Launch XenClient.exe under wine in background. version.dll + dom_replay.dll
#    are already dropped into /game by the host's `make hijack-install`, and
#    WINEDLLOVERRIDES=version=n tells wine's loader to prefer the native one
#    next to the EXE over the builtin.
# 6) After INJECT_DELAY (~12s) for DXRender + DLL attach, run dom_driver.py
#    in the foreground so the container exits when the replay finishes.
set -euo pipefail

log() { echo "[wine-client] $*"; }

DISPLAY_NUM="${DISPLAY_NUM:-99}"
export DISPLAY=":${DISPLAY_NUM}"
WINE_W="${WINE_W:-1440}"
WINE_H="${WINE_H:-975}"

# WINEDEBUG=-all by default to keep logs sane. Override via env for diagnostics
# (e.g. WINEDEBUG=-d3d,+winediag).
export WINEDEBUG="${WINEDEBUG:--all}"
export WINEPREFIX="${WINEPREFIX:-/wine}"
# WINEDLLOVERRIDES is intentionally NOT exported here — `version=n` would
# also apply to wineboot --init, which itself imports version.dll, and with
# no native version.dll available yet the loader fails. Set it inline only
# on the XenClient.exe launch below.
WINEDLLOVERRIDES_GAME="${WINEDLLOVERRIDES:-version=n}"
# new-wow64: 64-bit prefix runs 32-bit PEs (DXRender) via wow64 thunks. No linux/i386 ELFs.
# DXRender + dom_replay.dll + version.dll are all 32-bit PE. With wine 10
# built --enable-archs=x86_64, they load INTO the 64-bit wine process and
# execute as 32-bit code translated by Rosetta — qemu-i386 never runs, so the
# linux/i386 mmap-alignment crash that breaks wine 11 is sidestepped entirely.
export WINEARCH="${WINEARCH:-win64}"

mkdir -p /var/log

log "starting Xvfb on ${DISPLAY} at ${WINE_W}x${WINE_H}x24"
Xvfb "${DISPLAY}" -screen 0 "${WINE_W}x${WINE_H}x24" -nolisten tcp >/var/log/xvfb.log 2>&1 &
XVFB_PID=$!

# Wait up to 10s for Xvfb.
for _ in $(seq 1 50); do
  if xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
if ! xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
  log "ERROR: Xvfb never came up"
  exit 1
fi
log "Xvfb up (pid=${XVFB_PID})"

# One-time wineprefix init + GL compat regkeys. Persisted via the wineprefix
# named volume, so subsequent runs skip this.
#
# WINEDLLOVERRIDES="mscoree=,mshtml=" disables wine's auto-install of mono
# (.NET emulator) and gecko (HTML engine). Without this, wineboot --init
# hangs forever trying to download wine-mono.msi over the network — and our
# replay-net is internal:true with no internet access. DXRender doesn't need
# .NET or HTML rendering anyway.
if [[ ! -f "${WINEPREFIX}/system.reg" ]]; then
  log "initializing wineprefix at ${WINEPREFIX} (mono/gecko disabled)"
  WINEDLLOVERRIDES="mscoree=,mshtml=" wineboot --init >/var/log/wineboot.log 2>&1 || true
  # Block until wineserver settles.
  wineserver -w || true
  log "applying Direct3D GL compat regkeys"
  wine reg ADD 'HKCU\Software\Wine\Direct3D' /v MaxVersionGL /t REG_DWORD /d 0x00020000 /f
  wine reg ADD 'HKCU\Software\Wine\Direct3D' /v csmt /t REG_DWORD /d 0 /f
  wineserver -w || true
fi

# Wait for replay-server.
log "waiting for replay-server 10.42.0.10:1818"
for _ in $(seq 1 30); do
  if nc -z 10.42.0.10 1818 2>/dev/null; then
    log "replay-server reachable"
    break
  fi
  sleep 1
done
if ! nc -z 10.42.0.10 1818 2>/dev/null; then
  log "ERROR: replay-server not reachable on 10.42.0.10:1818 after 30s"
  exit 1
fi

# Resolve recording (mirrors server/entrypoint.sh).
SESSIONS_DIR="${SESSIONS_DIR:-/sessions}"
if [[ -n "${RECORDING_ID:-}" ]]; then
  JSONL="${SESSIONS_DIR}/recording_${RECORDING_ID}.jsonl"
  if [[ ! -f "${JSONL}" ]]; then
    log "ERROR: Recording not found: ${JSONL}"
    exit 1
  fi
else
  JSONL="$(ls -t "${SESSIONS_DIR}"/recording_*.jsonl 2>/dev/null | head -n1 || true)"
  if [[ -z "${JSONL}" || ! -f "${JSONL}" ]]; then
    log "ERROR: No recording_*.jsonl files in ${SESSIONS_DIR}"
    exit 1
  fi
fi
log "using recording: ${JSONL}"

# Launch wine in the background. /game is the read-only mount of the vendored
# install (XenClient.exe, DXRender.exe, version.dll, dom_replay.dll, etc).
TOKEN="${TOKEN:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
log "launching XenClient.exe under wine (token=${TOKEN:0:8}…)"
(
  cd /game
  WINEDLLOVERRIDES="${WINEDLLOVERRIDES_GAME}" wine XenClient.exe -I 10.42.0.10 -ID "${TOKEN}"
) >/var/log/wine.log 2>&1 &
WINE_PID=$!
log "wine pid=${WINE_PID}; sleeping INJECT_DELAY=${INJECT_DELAY:-12}s for DLL attach"

sleep "${INJECT_DELAY:-12}"

# Run the driver in the foreground. dom_driver.py defaults to ./screenshot.sh
# (line 309 of the file: `ap.add_argument("--screenshot-script", default="./screenshot.sh"`),
# so we pass the absolute path explicitly via --screenshot-script.
DRIVER_ARGS=(
  --recording "${JSONL}"
  --cmd-file "${WINEPREFIX}/dosdevices/c:/dom_cmd.txt"
  --log-file "${WINEPREFIX}/dosdevices/c:/dom_replay.log"
  --speed "${SPEED:-1.0}"
  --login-slot "${LOGIN_SLOT:-0}"
  --start-delay 0
  --match-timeout 8
  --screenshot-script /app/screenshot-x11.sh
)
if [[ -n "${SKIP_LOGIN:-}" ]]; then
  DRIVER_ARGS+=(--skip-login)
fi

log "launching dom_driver.py"
exec python3 -u /app/dom_driver.py "${DRIVER_ARGS[@]}"
