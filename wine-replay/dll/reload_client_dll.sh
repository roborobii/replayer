#!/bin/bash
# DLL-injection based client reload - replaces click-based reload_client.sh
# Usage: ./reload_client_dll.sh
# Requires: wine, i686-w64-mingw32-gcc (for recompile only)
set -e

PROJ="/Users/robin/proj"
WORKTREE="$PROJ"
CLIENT_DIR="$PROJ/solstice-client"
DLL_DIR="$PROJ/tools/dll"
SCREENSHOT="$PROJ/server-emulator-python3/tools/screenshot.sh"
AUTH_URL="http://127.0.0.2:8090/api/auth/login"
WINE_C="/Users/robin/.wine/dosdevices/c:/"

# Wine paths for DLLs (Z: = /)
WIN_DLL_DIR="Z:\\Users\\robin\\proj\\tools\\dll"

echo "=== Killing existing client ==="
wineserver -k 2>/dev/null || true
sleep 2

echo "=== Getting auth token ==="
TOKEN=$(curl -s -X POST "$AUTH_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"password"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "Token: $TOKEN (len=${#TOKEN})"

if [ -z "$TOKEN" ]; then
    echo "ERROR: Failed to get token. Is auth service running on port 8090?"
    exit 1
fi

# Write token to C:\token.txt for connect.dll to read
echo -n "$TOKEN" > "${WINE_C}token.txt"
echo "Wrote token to ${WINE_C}token.txt"

echo "=== Launching client ==="
cd "$CLIENT_DIR"
wine XenClient.exe -i 127.0.0.2 -t "$TOKEN" &
CLIENT_PID=$!

echo "=== Waiting for game window ==="
for i in $(seq 1 30); do
    # Check if the Wine window exists by looking for the process
    if pgrep -f "XenClient.exe" > /dev/null 2>&1; then
        # Try to find the window using winepath or just wait
        sleep 1
        if [ $i -ge 5 ]; then
            echo "Window should be up after ${i}s"
            break
        fi
    else
        sleep 1
    fi
done

# Extra wait for the game to fully initialize its ConnMgr
sleep 3
echo "=== Game window ready ==="

# Optionally inject trace.dll for debugging
if [ "${TRACE:-0}" = "1" ]; then
    echo "=== Injecting trace.dll (VEH packet tracer) ==="
    wine "$DLL_DIR/injector.exe" "${WIN_DLL_DIR}\\trace.dll" 2>&1 || true
    sleep 1
fi

echo "=== Injecting connect.dll (SVC connection + D3 login) ==="
wine "$DLL_DIR/injector.exe" "${WIN_DLL_DIR}\\connect.dll" 2>&1 || true
sleep 1

# Check connect.dll log
if [ -f "${WINE_C}connect.log" ]; then
    echo "--- connect.log ---"
    cat "${WINE_C}connect.log"
    echo "---"
fi

echo "=== Waiting for D3 response (2s) ==="
sleep 2

echo "=== Injecting charctl.dll (D5 create + D7 load) ==="
wine "$DLL_DIR/injector.exe" "${WIN_DLL_DIR}\\charctl.dll" 2>&1 || true

# charctl.dll has internal 2s delay for D3 response, then 1s for D7
echo "=== Waiting for character load (5s) ==="
sleep 5

# Check charctl.dll log
if [ -f "${WINE_C}charctl.log" ]; then
    echo "--- charctl.log ---"
    cat "${WINE_C}charctl.log"
    echo "---"
fi

echo "=== Taking screenshot ==="
if [ -x "$SCREENSHOT" ]; then
    bash "$SCREENSHOT" 2>/dev/null || echo "(screenshot failed)"
    echo "Screenshot saved to /tmp/game_client.jpg"
else
    echo "(screenshot.sh not found at $SCREENSHOT)"
fi

echo "=== Done! Client should be in-game ==="
echo "Logs: ${WINE_C}connect.log, ${WINE_C}charctl.log"
if [ "${TRACE:-0}" = "1" ]; then
    echo "Trace: ${WINE_C}trace.log"
fi
echo ""
echo "To probe game state:  wine $DLL_DIR/injector.exe '${WIN_DLL_DIR}\\probe.dll'"
echo "Probe log:            ${WINE_C}probe.log"
echo "For tracing:          TRACE=1 $0"
