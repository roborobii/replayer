#!/usr/bin/env bash
# Phase 3: Replay phase3_walk_v4.jsonl onto offline Wine client.
#
# Reproduces a recorded VM session byte-for-byte via pair_matcher:
#   master-server normal handler -> SVC pair-matched (D3+D4+D7) ->
#   chat pair-matched (B0) -> world cipher pair-matched (LLOGIN +
#   spawn bundle + ~14 in-world frames). Final state: offline lands
#   at Raito on the spawn hub, NPCs/players/chat/minimap rendered
#   from recorded VM data.
#
# One-shot:    bash 20260429_replay_phase3_walk_v4.txt
# Re-run safely: it tears down any prior Wine and recreates the
# emulator container at step 0.
#
# 2026-04-29

set -u
set -o pipefail

PROJ=/Users/robin/proj
RECORDING=recordings/phase3_walk_v4.jsonl

# 0. Hard reset
echo "[0] tearing down prior Wine + recreating emulator"
pkill -9 -f XenClient 2>/dev/null; pkill -9 -f DXRender 2>/dev/null
ps -eo pid,comm | grep '\.exe$' | awk '{print $1}' | xargs kill -9 2>/dev/null
sleep 3
: > ~/.wine/dosdevices/c:/dom_cmd.txt
: > ~/.wine/dosdevices/c:/dom_replay.log

cd "$PROJ/server-emulator-python3"
PAIR_MATCH=/app/$RECORDING docker compose \
  -f docker-compose.yml -f docker-compose.dev.yml \
  up -d --force-recreate game-server-1
sleep 5

# Verify pair_matcher loaded the recording + populated offline token
docker logs solstice-game-1 2>&1 | grep -E "PairMatch|trim|token-sub" | head -8

# 1. Read offline token (eager-fetched by emulator at PAIR_MATCH boot)
TOKEN=$(cat "$PROJ/server-emulator-python3/recorded_sessions/.offline_token")
echo "[1] offline token: $TOKEN"

# 2. Launch offline Wine client with that token
cd "$PROJ/new-solstice-client"
nohup wine XenClient.exe -i 127.0.0.2 -t "$TOKEN" \
  > /tmp/wine_client.log 2>&1 &
echo "[2] wine launched; sleeping 12s for Server Select to render"
sleep 12

# Sanity: DXRender is up
pgrep -fl DXRender.exe | head -1

# 3. Run the replayer (auto-injects DLL, drives form events, gates net)
cd "$PROJ"
echo "[3] running recording_replayer..."
python3 pipeline/recording_replayer.py "$RECORDING"
RC=$?

# 4. Screenshot the offline window
echo "[4] screenshot to /tmp/game_client.jpg"
bash "$PROJ/server-emulator-python3/tools/screenshot.sh" || true
ls -la /tmp/game_client.jpg

# 5. Done
if [ $RC -eq 0 ]; then
  echo ""
  echo "=== PASS ==="
  echo "Offline reached in-world. Open /tmp/game_client.jpg to see Raito"
  echo "at the spawn hub with VM-recorded NPCs/players/chat."
  echo ""
  echo "Note: offline will idle-disconnect ~30s after replay completes"
  echo "(end-of-recording; no autonomous server emit in PAIR_MATCH mode)."
else
  echo ""
  echo "=== FAIL ==="
  echo "Check emulator logs:"
  echo "  docker logs solstice-game-1 2>&1 | grep -iE 'PairMatch|desync|SVC/PM|World/PM|Chat/PM' | tail -30"
  echo "Check DLL log:    tail -20 ~/.wine/dosdevices/c:/dom_replay.log"
  echo "Check Wine log:   tail -20 /tmp/wine_client.log"
fi
exit $RC
