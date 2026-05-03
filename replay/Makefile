# Phase 2 control plane — Mac emulator + RC3 (offline T470) client.
#
# Pattern lifted from reverse-engineering-gc/PHASES/003 + 009: use Windows
# Task Scheduler with -LogonType Interactive to launch XenClient inside
# RC3's logged-in desktop session, since SSH-launched processes can't
# render GUI windows.
#
# Defaults assume:
#   - Mac at 192.168.12.148 binds emulator to 0.0.0.0
#   - RC3 at 192.168.12.188, user RC3, key ~/.ssh/xen_win_ed25519
#     (configured in ~/.ssh/config; `ssh RC3@192.168.12.188` Just Works)

MAC_IP       ?= 192.168.12.148
RC3_IP       ?= 192.168.12.188
RC3_USER     ?= RC3
RC3          := $(RC3_USER)@$(RC3_IP)
RECORDING_ID ?= smoke5
TOKEN        ?= 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
PYTHON       ?= python3

# Click-coordinate tuning (pixels in target screen). Positive Y = clicks lower.
X_CORRECTION ?= 0
Y_CORRECTION ?= 5

SSH          := ssh
SCP          := scp

CLIENT_REMOTE_DIR := C:/work/solstice-client/XenRebirth_Xenepic
CLIENT_REMOTE_EXE := $(CLIENT_REMOTE_DIR)/XenClient.exe
CLIENT_CFG        := $(CLIENT_REMOTE_DIR)/Data/CLIENT.CFG
FULLSCREEN        ?= 1

REPLAY_REMOTE := C:/Users/RC3/replay
PYTHON_REMOTE := C:/Tools/python311/python.exe

REPO_ROOT := $(realpath ..)
SESSIONS  := $(REPO_ROOT)/sessions
JSONL     := $(SESSIONS)/recording_$(RECORDING_ID).jsonl

.PHONY: help server server-bg server-stop status rc3-up deploy fullscreen \
        run kill input input-stop replay clean-tasks

help:
	@echo "Phase 2 targets:"
	@echo "  server       start emulator FOREGROUND with $(JSONL) (Ctrl+C to stop)"
	@echo "  server-bg    start emulator in background; logs in /tmp/v2_server.log"
	@echo "  server-stop  kill any running emulator"
	@echo "  status       show :1818/:1819/:18123/:18124 listeners on Mac"
	@echo "  rc3-up       ssh reachability check on $(RC3_IP):22"
	@echo "  deploy       scp input_replayer + recording $(RECORDING_ID) to RC3"
	@echo "  fullscreen   set CLIENT.CFG[83] = $(FULLSCREEN) on RC3 (windowed=0)"
	@echo "  run          Task-Scheduler launch XenClient -I $(MAC_IP) -ID <token> on RC3"
	@echo "  kill         stop XenClient/DXRender/GLRender on RC3"
	@echo "  input        Task-Scheduler launch input_replayer.py on RC3"
	@echo "  input-stop   stop the input replayer task"
	@echo "  replay       full pipeline: server-bg + deploy + fullscreen + run + sleep + input"
	@echo "  clean-tasks  unregister scheduled tasks (xen-launch, xen-replay-input)"

server:
	@pkill -f 'v2_server.py' 2>/dev/null || true
	$(PYTHON) -u v2_server.py $(JSONL) --bind 0.0.0.0 --rewrite-host $(MAC_IP)

server-bg:
	@pkill -f 'v2_server.py' 2>/dev/null || true
	@nohup $(PYTHON) -u v2_server.py $(JSONL) --bind 0.0.0.0 --rewrite-host $(MAC_IP) > /tmp/v2_server.log 2>&1 &
	@sleep 1
	@head -6 /tmp/v2_server.log
	@echo "[server-bg] tail -f /tmp/v2_server.log"

server-stop:
	@pkill -f 'v2_server.py' 2>/dev/null && echo "[server-stop] killed" || echo "[server-stop] none running"

status:
	@for port in 1818 1819 18123 18124; do \
		out=$$(lsof -nP -iTCP:$$port -sTCP:LISTEN 2>/dev/null | tail -n +2); \
		if [ -z "$$out" ]; then echo "  :$$port not listening"; \
		else echo "$$out" | awk -v p=$$port '{print "  :"p" pid="$$2" "$$1}'; fi; \
	done

rc3-up:
	@nc -z -w 2 $(RC3_IP) 22 && echo "[ok] $(RC3_IP):22 reachable" \
		|| (echo "[fail] $(RC3_IP):22 unreachable"; exit 1)

deploy: rc3-up
	@test -f $(JSONL) || (echo "[deploy] missing $(JSONL)"; exit 1)
	$(SCP) input_replayer.py play-rc3.ps1 run_input.bat schedule_input.ps1 $(RC3):replay/
	$(SCP) _tools/resize_window.ps1 _tools/window_info.ps1 $(RC3):replay/
	$(SCP) $(SESSIONS)/recording_$(RECORDING_ID).jsonl $(RC3):replay/
	$(SCP) $(SESSIONS)/recording_$(RECORDING_ID).manifest.json $(RC3):replay/
	@echo "[deploy] OK"

fullscreen:
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "$$f=\"$(CLIENT_CFG)\"; $$b=[IO.File]::ReadAllBytes($$f); $$b[83]=[byte]$(FULLSCREEN); [IO.File]::WriteAllBytes($$f,$$b); \"CLIENT.CFG[83] = 0x{0:X2}\" -f $$b[83]"'

run: fullscreen
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "$$action = New-ScheduledTaskAction -Execute \"$(CLIENT_REMOTE_EXE)\" -Argument \"-I $(MAC_IP) -ID $(TOKEN)\" -WorkingDirectory \"$(CLIENT_REMOTE_DIR)\"; $$principal = New-ScheduledTaskPrincipal -UserId RC3 -RunLevel Highest -LogonType Interactive; $$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 8); $$task = New-ScheduledTask -Action $$action -Principal $$principal -Settings $$settings; Register-ScheduledTask -TaskName xen-launch -InputObject $$task -Force | Out-Null; Start-ScheduledTask -TaskName xen-launch; Start-Sleep -Seconds 2; Get-Process DXRender,GLRender,XenClient -ErrorAction SilentlyContinue | Select-Object Name,Id,SessionId | Format-Table -AutoSize | Out-String; exit 0"'

kill:
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "Get-Process XenClient,DXRender,GLRender -ErrorAction SilentlyContinue | Stop-Process -Force; exit 0"'

# Force the game window to exactly 1440x900 client area at (0,0) so the
# replay frame matches the recording's vmconnect 1440x900 game area.
# Note: requires windowed mode (FULLSCREEN=0) since fullscreen ignores MoveWindow.
resize:
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "$$action = New-ScheduledTaskAction -Execute powershell.exe -Argument \"-NoProfile -ExecutionPolicy Bypass -File $(REPLAY_REMOTE)/resize_window.ps1\" -WorkingDirectory $(REPLAY_REMOTE); $$principal = New-ScheduledTaskPrincipal -UserId RC3 -RunLevel Highest -LogonType Interactive; $$task = New-ScheduledTask -Action $$action -Principal $$principal; Register-ScheduledTask -TaskName xen-resize -InputObject $$task -Force | Out-Null; Start-ScheduledTask -TaskName xen-resize; Start-Sleep -Seconds 3; Get-Content $(REPLAY_REMOTE)/resize.log -ErrorAction SilentlyContinue"'

input:
	@$(SSH) $(RC3) 'powershell -NoProfile -ExecutionPolicy Bypass -File $(REPLAY_REMOTE)/schedule_input.ps1 -RecordingId $(RECORDING_ID) -XCorrection $(X_CORRECTION) -YCorrection $(Y_CORRECTION) -CtrlHost $(MAC_IP)'

input-stop:
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "Stop-ScheduledTask -TaskName xen-replay-input -ErrorAction SilentlyContinue; exit 0"'

replay: server-bg
	@echo "[replay] emulator up. launching client..."
	@$(MAKE) run
	@$(MAKE) resize
	@echo ""
	@echo "[replay] DXRender is up. The Mac emulator will pair-match your"
	@echo "[replay] clicks against the recorded session. Click servers,"
	@echo "[replay] characters etc. on RC3 normally; recorded server"
	@echo "[replay] responses get sent back automatically."
	@echo "[replay] Tail Mac log:  tail -f /tmp/v2_server.log"

# Optional unattended replay (drives clicks from JSONL too). Mostly for
# automation; for interactive use just `make replay` and click yourself.
auto-replay: deploy server-bg
	@$(MAKE) run FULLSCREEN=0
	@$(MAKE) resize
	@echo "[auto-replay] sleeping 7s for handshake + server-select render"
	@sleep 7
	@$(MAKE) input

clean-tasks:
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "Unregister-ScheduledTask -TaskName xen-launch -Confirm:$$false -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName xen-replay-input -Confirm:$$false -ErrorAction SilentlyContinue; exit 0"'
