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
RC_IP        ?= 192.168.12.196
RC_USER      ?= RC
RC           := $(RC_USER)@$(RC_IP)
RC_SESSIONS  := C:/Users/RC/sessions
RECORDING_ID ?= smoke5
TOKEN        ?= 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
PYTHON       ?= python3

# Click-coordinate tuning (pixels in target screen). Positive Y = clicks lower.
X_CORRECTION ?= 0
Y_CORRECTION ?= 5

# Click delivery: sendinput (default) or postmessage (no cursor move, posts
# WM_LBUTTONDOWN/UP directly to XenClient's HWND).
CLICK_MODE   ?= sendinput

# Replay speed multiplier. 1.0 = recorded pace (default).
# 2.0 = scale every inter-event delta to half (input + S2C in lockstep).
# Sequence is preserved; only inter-event deltas shrink. The Mac
# emulator's S2C pacing scales identically so server packets stay aligned
# with input. >1.0 is best-effort: the game client itself runs in real
# time, so animations / movement that depend on its internal clock can't
# go faster than the client renders them.
SPEED        ?= 1.0

SSH          := ssh
SCP          := scp

CLIENT_REMOTE_DIR := C:/work/solstice-client/XenRebirth_Xenepic
CLIENT_REMOTE_EXE := $(CLIENT_REMOTE_DIR)/XenClient.exe
CLIENT_CFG        := $(CLIENT_REMOTE_DIR)/Data/CLIENT.CFG
FULLSCREEN        ?= 1

REPLAY_REMOTE := C:/Users/RC3/replay
RECORDER_REMOTE := C:/Users/RC/recorder
PYTHON_REMOTE := C:/Tools/python311/python.exe

REPO_ROOT := $(realpath ..)
SESSIONS  := $(REPO_ROOT)/sessions
RECORDER_DIR := $(REPO_ROOT)/recorder
JSONL     := $(SESSIONS)/recording_$(RECORDING_ID).jsonl

.PHONY: help server server-bg server-stop status rc-up rc3-up deploy \
        deploy-recorder fullscreen run kill input input-stop replay auto-replay \
        _auto-replay clean-tasks list-sessions pull-sessions install-cv2 \
        cv-calibrate neutralize

help:
	@echo "Phase 2 targets:"
	@echo "  server       start emulator FOREGROUND with $(JSONL) (Ctrl+C to stop)"
	@echo "  server-bg    start emulator in background; logs in /tmp/v2_server.log"
	@echo "  server-stop  kill any running emulator"
	@echo "  status       show :1818/:1819/:18123/:18124 listeners on Mac"
	@echo "  rc3-up       ssh reachability check on $(RC3_IP):22"
	@echo "  rc-up        ssh reachability check on $(RC_IP):22"
	@echo "  deploy       scp input_replayer + recording $(RECORDING_ID) to RC3"
	@echo "  deploy-recorder scp recorder/{host-record-v2.ps1,host_recording_stream_v2.py,v2cipher.py} to RC ($(RC_IP))"
	@echo "  fullscreen   set CLIENT.CFG[83] = $(FULLSCREEN) on RC3 (windowed=0)"
	@echo "  run          Task-Scheduler launch XenClient -I $(MAC_IP) -ID <token> on RC3"
	@echo "  kill         stop XenClient/DXRender/GLRender on RC3"
	@echo "  input        Task-Scheduler launch input_replayer.py on RC3"
	@echo "  input-stop   stop the input replayer task"
	@echo "  replay       full pipeline: server-bg + deploy + fullscreen + run + sleep + input"
	@echo "  clean-tasks  unregister scheduled tasks (xen-launch, xen-replay-input)"
	@echo "  list-sessions   list recordings on RC ($(RC_IP))"
	@echo "  pull-sessions   scp the LATEST recording (by mtime) from RC -> sessions/. Pass RECORDING_ID=<id> to pull a specific one (or RECORDING_ID=ALL for everything)."
	@echo "  install-cv2     download Win cp311 wheels (cv2,numpy,Pillow) on Mac, scp + offline pip install on RC3"
	@echo "  cv-calibrate    SEQ=<n> RECORDING_ID=<id>: run replayer's CV match against live RC3 game window; pull annotated PNG to /tmp/cv_calibrate_<seq>.png"

server:
	@pkill -f 'v2_server.py' 2>/dev/null || true
	$(PYTHON) -u v2_server.py $(JSONL) --bind 0.0.0.0 --rewrite-host $(MAC_IP) --speed $(SPEED)

server-bg:
	@pkill -9 -f 'v2_server.py' 2>/dev/null || true
	@for port in 1818 1819 18123 18124; do \
		pid=$$(lsof -nP -iTCP:$$port -sTCP:LISTEN -t 2>/dev/null); \
		[ -n "$$pid" ] && kill -9 $$pid 2>/dev/null || true; \
	done
	@sleep 0.5
	@nohup $(PYTHON) -u v2_server.py $(JSONL) --bind 0.0.0.0 --rewrite-host $(MAC_IP) --speed $(SPEED) > /tmp/v2_server.log 2>&1 &
	@sleep 1
	@head -10 /tmp/v2_server.log
	@if grep -q 'Address already in use' /tmp/v2_server.log; then echo "[server-bg] FAIL: port already in use — see log"; exit 1; fi
	@echo "[server-bg] tail -f /tmp/v2_server.log"

server-stop:
	@pkill -9 -f 'v2_server.py' 2>/dev/null && echo "[server-stop] killed" || echo "[server-stop] none running"

status:
	@for port in 1818 1819 18123 18124; do \
		out=$$(lsof -nP -iTCP:$$port -sTCP:LISTEN 2>/dev/null | tail -n +2); \
		if [ -z "$$out" ]; then echo "  :$$port not listening"; \
		else echo "$$out" | awk -v p=$$port '{print "  :"p" pid="$$2" "$$1}'; fi; \
	done

rc3-up:
	@nc -z -w 2 $(RC3_IP) 22 && echo "[ok] $(RC3_IP):22 reachable" \
		|| (echo "[fail] $(RC3_IP):22 unreachable"; exit 1)

rc-up:
	@nc -z -w 2 $(RC_IP) 22 && echo "[ok] $(RC_IP):22 reachable" \
		|| (echo "[fail] $(RC_IP):22 unreachable"; exit 1)

# Push the recorder bundle to RC ($(RC_IP)). RC has no internet — this is the
# canonical way to sync the three files that host-record-v2.ps1 expects under
# C:\Users\RC\recorder\. Idempotent.
deploy-recorder: rc-up
	@for f in host-record-v2.ps1 host_recording_stream_v2.py v2cipher.py; do \
		test -f $(RECORDER_DIR)/$$f || (echo "[deploy-recorder] missing $(RECORDER_DIR)/$$f"; exit 1); \
	done
	$(SCP) $(RECORDER_DIR)/host-record-v2.ps1 $(RECORDER_DIR)/host_recording_stream_v2.py $(RECORDER_DIR)/v2cipher.py $(RC):recorder/
	@echo "[deploy-recorder] OK -> $(RC):$(RECORDER_REMOTE)/"

deploy: rc3-up
	@test -f $(JSONL) || (echo "[deploy] missing $(JSONL)"; exit 1)
	$(SCP) input_replayer.py spawn_parser.py play-rc3.ps1 run_input.bat schedule_input.ps1 $(RC3):replay/
	$(SCP) _tools/resize_window.ps1 _tools/window_info.ps1 _tools/rc3_screenshot.ps1 $(RC3):replay/
	$(SCP) $(SESSIONS)/recording_$(RECORDING_ID).jsonl $(RC3):replay/
	$(SCP) $(SESSIONS)/recording_$(RECORDING_ID).manifest.json $(RC3):replay/
	-$(SCP) -r $(SESSIONS)/recording_$(RECORDING_ID)_patches $(RC3):replay/
	@echo "[deploy] OK"

fullscreen:
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "$$f=\"$(CLIENT_CFG)\"; $$b=[IO.File]::ReadAllBytes($$f); $$b[83]=[byte]$(FULLSCREEN); [IO.File]::WriteAllBytes($$f,$$b); \"CLIENT.CFG[83] = 0x{0:X2}\" -f $$b[83]"'

run: fullscreen
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "$$action = New-ScheduledTaskAction -Execute \"$(CLIENT_REMOTE_EXE)\" -Argument \"-I $(MAC_IP) -ID $(TOKEN)\" -WorkingDirectory \"$(CLIENT_REMOTE_DIR)\"; $$principal = New-ScheduledTaskPrincipal -UserId RC3 -RunLevel Highest -LogonType Interactive; $$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 8); $$task = New-ScheduledTask -Action $$action -Principal $$principal -Settings $$settings; Register-ScheduledTask -TaskName xen-launch -InputObject $$task -Force | Out-Null; Start-ScheduledTask -TaskName xen-launch; Start-Sleep -Seconds 2; Get-Process DXRender,GLRender,XenClient -ErrorAction SilentlyContinue | Select-Object Name,Id,SessionId | Format-Table -AutoSize | Out-String; exit 0"'

cv-debug-pull:
	@mkdir -p $(SESSIONS)/cv_debug_$(RECORDING_ID)
	-$(SCP) -r $(RC3):replay/cv_debug/* $(SESSIONS)/cv_debug_$(RECORDING_ID)/
	@echo "[cv-debug-pull] -> $(SESSIONS)/cv_debug_$(RECORDING_ID)/"

# Calibrate the replayer's CV pipeline for a single recorded click. Runs
# cv_calibrate.py on RC3 — same Python, same input_replayer.py, same
# screenshot_window/cv_match_patch — so the annotated PNG reflects what
# the replayer would actually do for that event.
#
# Usage: make cv-calibrate RECORDING_ID=mage-v4-aoe-with-chainblock SEQ=276
cv-calibrate:
	@test -n "$(SEQ)" || (echo "[cv-calibrate] usage: make cv-calibrate RECORDING_ID=<id> SEQ=<n> [CURSOR_MASK_PX=<n>]"; exit 1)
	$(SCP) cv_calibrate.py cv_calibrate.ps1 input_replayer.py spawn_parser.py $(RC3):replay/
	@$(SSH) $(RC3) 'powershell -NoProfile -ExecutionPolicy Bypass -File $(REPLAY_REMOTE)/cv_calibrate.ps1 -RecordingId $(RECORDING_ID) -Seq $(SEQ) -CursorMaskPx $(if $(CURSOR_MASK_PX),$(CURSOR_MASK_PX),0)'
	$(SCP) $(RC3):replay/cv_calibrate_$(SEQ).png /tmp/cv_calibrate_$(SEQ).png
	@echo "[cv-calibrate] -> /tmp/cv_calibrate_$(SEQ).png"

cv-debug-clean:
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "Remove-Item -Recurse -Force $(REPLAY_REMOTE)/cv_debug -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Path $(REPLAY_REMOTE)/cv_debug | Out-Null"'

kill: server-stop
	$(SCP) kill_replayer.ps1 $(RC3):replay/ 2>/dev/null || true
	@$(SSH) $(RC3) 'powershell -NoProfile -ExecutionPolicy Bypass -File $(REPLAY_REMOTE)/kill_replayer.ps1'
	@$(MAKE) --no-print-directory neutralize
	@echo "[kill] RC3 client + input_replayer + scheduled tasks + Mac v2_server stopped + input neutralized"

# Release any modifier keys / mouse buttons stuck on RC3 from a halted
# replay or interrupted Alt-shortcut/drag. Schedules a one-shot
# interactive task so SendInput delivers to the user's session.
neutralize:
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "$$action = New-ScheduledTaskAction -Execute $(PYTHON_REMOTE) -Argument \"$(REPLAY_REMOTE)\\input_replayer.py --neutralize-only\" -WorkingDirectory $(REPLAY_REMOTE); $$principal = New-ScheduledTaskPrincipal -UserId RC3 -RunLevel Highest -LogonType Interactive; $$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden; $$task = New-ScheduledTask -Action $$action -Principal $$principal -Settings $$settings; Register-ScheduledTask -TaskName xen-neutralize -InputObject $$task -Force | Out-Null; Start-ScheduledTask -TaskName xen-neutralize; Start-Sleep -Milliseconds 600; Unregister-ScheduledTask -TaskName xen-neutralize -Confirm:$$false -ErrorAction SilentlyContinue | Out-Null"'
	@echo "[neutralize] RC3 modifiers + mouse buttons released"

# Force the game window to exactly 1440x900 client area at (0,0) so the
# replay frame matches the recording's vmconnect 1440x900 game area.
# Note: requires windowed mode (FULLSCREEN=0) since fullscreen ignores MoveWindow.
resize:
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "$$action = New-ScheduledTaskAction -Execute powershell.exe -Argument \"-NoProfile -ExecutionPolicy Bypass -File $(REPLAY_REMOTE)/resize_window.ps1\" -WorkingDirectory $(REPLAY_REMOTE); $$principal = New-ScheduledTaskPrincipal -UserId RC3 -RunLevel Highest -LogonType Interactive; $$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; $$task = New-ScheduledTask -Action $$action -Principal $$principal -Settings $$settings; Register-ScheduledTask -TaskName xen-resize -InputObject $$task -Force | Out-Null; Start-ScheduledTask -TaskName xen-resize; Start-Sleep -Seconds 3; Get-Content $(REPLAY_REMOTE)/resize.log -ErrorAction SilentlyContinue"'

screenshot:
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "$$action = New-ScheduledTaskAction -Execute powershell.exe -Argument \"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $(REPLAY_REMOTE)/rc3_screenshot.ps1\" -WorkingDirectory $(REPLAY_REMOTE); $$principal = New-ScheduledTaskPrincipal -UserId RC3 -RunLevel Highest -LogonType Interactive; $$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden; $$task = New-ScheduledTask -Action $$action -Principal $$principal -Settings $$settings; Register-ScheduledTask -TaskName xen-screenshot -InputObject $$task -Force | Out-Null; Start-ScheduledTask -TaskName xen-screenshot; Start-Sleep -Seconds 3"'
	$(SCP) $(RC3):replay/rc3_screen.png /tmp/rc3_screen.png
	@echo "[screenshot] -> /tmp/rc3_screen.png"

input:
	@$(SSH) $(RC3) 'powershell -NoProfile -ExecutionPolicy Bypass -File $(REPLAY_REMOTE)/schedule_input.ps1 -RecordingId $(RECORDING_ID) -XCorrection $(X_CORRECTION) -YCorrection $(Y_CORRECTION) -CtrlHost $(MAC_IP) -ClickMode $(CLICK_MODE) -Speed $(SPEED) $(if $(CV_DEBUG),-CvDebugDir "$(REPLAY_REMOTE)/cv_debug",)'

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
# Defaults to the latest local recording (by mtime); pass RECORDING_ID=<id>
# to pin a specific one.
auto-replay:
ifeq ($(origin RECORDING_ID),command line)
	@$(MAKE) --no-print-directory _auto-replay RECORDING_ID=$(RECORDING_ID)
else
	@id=$$(ls -t $(SESSIONS)/recording_*.jsonl 2>/dev/null | head -n1 | sed -e 's|.*/recording_||' -e 's|\.jsonl$$||'); \
	[ -n "$$id" ] || (echo "[auto-replay] no local recordings under $(SESSIONS)/ — run 'make pull-sessions' first"; exit 1); \
	echo "[auto-replay] latest local recording: $$id"; \
	$(MAKE) --no-print-directory _auto-replay RECORDING_ID=$$id
endif

_auto-replay: deploy server-bg
	@$(MAKE) run FULLSCREEN=0
	@$(MAKE) resize
	@echo "[_auto-replay] sleeping 3s for handshake + server-select render"
	@sleep 3
	@$(MAKE) input

clean-tasks:
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "Unregister-ScheduledTask -TaskName xen-launch -Confirm:$$false -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName xen-replay-input -Confirm:$$false -ErrorAction SilentlyContinue; exit 0"'

list-sessions:
	@$(SSH) $(RC) 'powershell -NoProfile -Command "Get-ChildItem $(RC_SESSIONS)\\recording_*.jsonl | Sort-Object LastWriteTime -Descending | Select-Object Name,@{N=\"MB\";E={[math]::Round($$_.Length/1MB,2)}},LastWriteTime | Format-Table -AutoSize"'

pull-sessions:
	@mkdir -p $(SESSIONS)
ifeq ($(RECORDING_ID),ALL)
	$(SCP) '$(RC):$(RC_SESSIONS)/recording_*.jsonl' $(SESSIONS)/
	-$(SCP) '$(RC):$(RC_SESSIONS)/recording_*.manifest.json' $(SESSIONS)/
	-$(SCP) '$(RC):$(RC_SESSIONS)/recording_*.pcap' $(SESSIONS)/
	-$(SCP) -r '$(RC):$(RC_SESSIONS)/recording_*_patches' $(SESSIONS)/
	@echo "[pull-sessions] OK: all recordings + patches -> $(SESSIONS)/"
else ifeq ($(origin RECORDING_ID),command line)
	@echo "[pull-sessions] pulling specified: $(RECORDING_ID)"
	$(SCP) '$(RC):$(RC_SESSIONS)/recording_$(RECORDING_ID).jsonl' $(SESSIONS)/
	-$(SCP) '$(RC):$(RC_SESSIONS)/recording_$(RECORDING_ID).manifest.json' $(SESSIONS)/
	-$(SCP) '$(RC):$(RC_SESSIONS)/recording_$(RECORDING_ID).pcap' $(SESSIONS)/
	-$(SCP) -r '$(RC):$(RC_SESSIONS)/recording_$(RECORDING_ID)_patches' $(SESSIONS)/
	@echo "[pull-sessions] OK: $(RECORDING_ID) -> $(SESSIONS)/"
else
	@id=$$($(SSH) $(RC) 'powershell -NoProfile -Command "(Get-ChildItem $(RC_SESSIONS)\\recording_*.jsonl | Sort-Object LastWriteTime -Descending | Select-Object -First 1).BaseName"' | tr -d '\r' | sed 's/^recording_//'); \
	[ -n "$$id" ] || (echo "[pull-sessions] no recordings found on $(RC)"; exit 1); \
	echo "[pull-sessions] latest on $(RC): $$id"; \
	$(SCP) "$(RC):$(RC_SESSIONS)/recording_$$id.jsonl" $(SESSIONS)/ && \
	{ $(SCP) "$(RC):$(RC_SESSIONS)/recording_$$id.manifest.json" $(SESSIONS)/ || true; } && \
	{ $(SCP) "$(RC):$(RC_SESSIONS)/recording_$$id.pcap" $(SESSIONS)/ || true; } && \
	{ $(SCP) -r "$(RC):$(RC_SESSIONS)/recording_$${id}_patches" $(SESSIONS)/ || true; } && \
	echo "[pull-sessions] OK: $$id -> $(SESSIONS)/"
endif

# RC3 has no internet AND ships the embeddable Python distro (no pip,
# no ensurepip). Download Windows cp311 wheels (incl. pip itself) on
# Mac, scp them to RC3, then run pip directly from its wheel zipapp
# to install everything offline. Idempotent — safe to re-run.
CV2_WHEEL_DIR := _vendor/cv2-wheels
install-cv2:
	@mkdir -p $(CV2_WHEEL_DIR)
	@echo "[install-cv2] downloading wheels for win_amd64 cp311..."
	@$(PYTHON) -m pip download \
		--platform win_amd64 \
		--python-version 3.11 \
		--implementation cp \
		--abi cp311 \
		--only-binary=:all: \
		--dest $(CV2_WHEEL_DIR) \
		opencv-python-headless numpy Pillow pywin32
	@$(PYTHON) -m pip download --dest $(CV2_WHEEL_DIR) pip setuptools
	@echo "[install-cv2] scp -> RC3:replay/_wheels/"
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path $(REPLAY_REMOTE)/_wheels | Out-Null"'
	$(SCP) $(CV2_WHEEL_DIR)/*.whl $(RC3):replay/_wheels/
	@echo "[install-cv2] bootstrapping pip + installing wheels on RC3..."
	@$(SSH) $(RC3) 'powershell -NoProfile -Command "$$pipwheel = (Get-ChildItem $(REPLAY_REMOTE)/_wheels/pip-*.whl | Select-Object -First 1).FullName; & $(PYTHON_REMOTE) $$pipwheel/pip install --no-index --find-links=$(REPLAY_REMOTE)/_wheels setuptools opencv-python-headless numpy Pillow pywin32"'
	@echo "[install-cv2] verifying on RC3..."
	@$(SSH) $(RC3) "$(PYTHON_REMOTE) -c \"import cv2, numpy, PIL, win32gui; print('cv2', cv2.__version__); print('numpy', numpy.__version__); print('Pillow', PIL.__version__); print('pywin32 OK')\""
	@echo "[install-cv2] OK"
