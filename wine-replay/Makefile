# wine-replay — replay a recorded session locally on this Mac via Wine.
#
# Server side (Mac native): v2_server.py binds BIND_IP and feeds back recorded
# S2C frames paced against t_mono_ns.
#
# Client side (Wine): XenClient.exe launched under wine, pointed at BIND_IP.
# WINEPREFIX's /etc/hosts equivalent is the Mac's /etc/hosts; combined with
# BIND_IP=127.0.0.3 (loopback alias), the client cannot reach the live server
# even if it tried. Add a pf rule on the wine uid for hard isolation.
#
# Input replay: instead of SendInput taking over the Mac mouse, drive in-game
# clicks by injecting dom_replay.dll into the wine'd client (~/proj/tools/dll/).
# That DLL polls C:\dom_cmd.txt and synthesizes clicks via the game's own
# internal mouse-handler VAs — purely in-process, no Mac input hijack.

BIND_IP       ?= 127.0.0.3
RECORDING_ID  ?=
TOKEN         ?= 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SPEED         ?= 1.0
PYTHON        ?= python3

WINE          ?= /opt/homebrew/bin/wine
WINESERVER    ?= $(WINE)server
WINEPREFIX    ?= $(HOME)/.wine
WINE_C        := $(WINEPREFIX)/dosdevices/c:

# Vendored locations inside this folder. Game payload is pulled in by
# `make vendor-client` (gitignored), DLL toolchain is committed.
CLIENT_DIR    ?= $(CURDIR)/client
CLIENT_EXE    ?= XenClient.exe
DLL_DIR       ?= $(CURDIR)/dll

# Source to vendor from. Override if your install lives elsewhere.
SRC_CLIENT    ?= $(HOME)/proj/new-solstice-client

REPO_ROOT := $(realpath ..)
SESSIONS  := $(REPO_ROOT)/sessions

# Resolve JSONL: explicit RECORDING_ID wins, else latest by mtime.
ifneq ($(RECORDING_ID),)
JSONL := $(SESSIONS)/recording_$(RECORDING_ID).jsonl
else
JSONL := $(shell ls -t $(SESSIONS)/recording_*.jsonl 2>/dev/null | head -n1)
endif

SWAP_FLAG := $(if $(SWAP_WITH_CHARACTER),--swap-with-character '$(SWAP_WITH_CHARACTER)',)

.PHONY: help server server-bg server-stop status wine kill replay \
        dom-cmd dll-inject dll-input scan isolate-help isolate-status isolate-test \
        isolate-require vendor-client vendor-status \
        setup setup-deps setup-loopback setup-isolate setup-verify \
        setup-uninstall full-replay \
        hijack-build hijack-install hijack-uninstall gl-compat \
        replay-go full-replay-hijack

help:
	@echo "wine-replay targets:"
	@echo "  server          run v2_server.py FOREGROUND, bind=$(BIND_IP), recording=$(JSONL)"
	@echo "  server-bg       background; logs in /tmp/v2_server.log"
	@echo "  server-stop     pkill v2_server.py"
	@echo "  status          show :1818/:1819/:18123/:18124 listeners on $(BIND_IP)"
	@echo "  wine            launch $(CLIENT_EXE) under wine, -I $(BIND_IP) -ID <token>  [gated on isolate-require]"
	@echo "  kill            stop wine client + v2_server"
	@echo "  replay          server-bg + wine                                                [gated on isolate-require]"
	@echo "  dll-inject DLL=<name>.dll      inject DLL into running wine client (legacy; broken on wine 10)"
	@echo "  dom-cmd CMD='probe'            write command to C:\\dom_cmd.txt"
	@echo "  dll-input                      drive recorded clicks via dom_replay.dll (no Mac input)"
	@echo "  full-replay                    LEGACY end-to-end via injection (wine 10 wow64 crashes)"
	@echo ""
	@echo "  hijack-build                   build dll/version.dll (DLL-hijack proxy)"
	@echo "  hijack-install                 copy version.dll + dom_replay.dll into client/"
	@echo "  hijack-uninstall               remove the dropped DLLs"
	@echo "  full-replay-hijack             end-to-end via DLL hijack (gates on isolate-require)"
	@echo "  replay-go                      end-to-end, skips runtime sudo gate (RECOMMENDED)"
	@echo ""
	@echo "  isolate-help    one-time install steps for the pf prod-IP block"
	@echo "  isolate-status  show pf state + wine-replay anchor rules (needs sudo)"
	@echo "  isolate-test    nc to $(PROD_IP):1818 — expect timeout"
	@echo "  isolate-require gate that wine/replay use; fails if pf anchor isn't loaded"
	@echo ""
	@echo "  vendor-client   rsync $(SRC_CLIENT) -> ./client (gitignored)"
	@echo "  vendor-status   check that ./client and ./dll are populated"
	@echo ""
	@echo "  setup           one-shot bootstrap on a fresh Mac (sudo): loopback alias + pf anchor"
	@echo "  setup-verify    re-run setup checks"
	@echo "  setup-uninstall reverse setup (remove pf anchor + LaunchDaemon)"
	@echo ""
	@echo "Vars: BIND_IP=$(BIND_IP) RECORDING_ID=$(RECORDING_ID) SPEED=$(SPEED) PROD_IP=$(PROD_IP)"
	@echo "      WINE=$(WINE) WINEPREFIX=$(WINEPREFIX)"
	@echo "      CLIENT_DIR=$(CLIENT_DIR)"
	@echo "      DLL_DIR=$(DLL_DIR)"

server:
	@test -n "$(JSONL)" || (echo "[server] no recording found in $(SESSIONS)/"; exit 1)
	@test -f "$(JSONL)" || (echo "[server] missing $(JSONL)"; exit 1)
	@pkill -f 'v2_server.py' 2>/dev/null || true
	$(PYTHON) -u v2_server.py $(JSONL) --bind $(BIND_IP) --rewrite-host $(BIND_IP) --speed $(SPEED) $(SWAP_FLAG)

server-bg:
	@test -n "$(JSONL)" || (echo "[server-bg] no recording found in $(SESSIONS)/"; exit 1)
	@test -f "$(JSONL)" || (echo "[server-bg] missing $(JSONL)"; exit 1)
	@pkill -9 -f 'v2_server.py' 2>/dev/null || true
	@for port in 1818 1819 18123 18124; do \
		pid=$$(lsof -nP -iTCP:$(BIND_IP):$$port -sTCP:LISTEN -t 2>/dev/null); \
		[ -n "$$pid" ] && kill -9 $$pid 2>/dev/null || true; \
	done
	@sleep 0.5
	@nohup $(PYTHON) -u v2_server.py $(JSONL) --bind $(BIND_IP) --rewrite-host $(BIND_IP) --speed $(SPEED) --world-lookahead-seq 999999 --world-gate-timeout-s 0.5 $(SWAP_FLAG) > /tmp/v2_server.log 2>&1 &
	@sleep 1
	@head -10 /tmp/v2_server.log
	@if grep -q 'Address already in use' /tmp/v2_server.log; then echo "[server-bg] FAIL: port already in use"; exit 1; fi
	@echo "[server-bg] tail -f /tmp/v2_server.log"

server-stop:
	@pkill -9 -f 'v2_server.py' 2>/dev/null && echo "[server-stop] killed" || echo "[server-stop] none running"

status:
	@for port in 1818 1819 18123 18124; do \
		out=$$(lsof -nP -iTCP:$(BIND_IP):$$port -sTCP:LISTEN 2>/dev/null | tail -n +2); \
		if [ -z "$$out" ]; then echo "  $(BIND_IP):$$port not listening"; \
		else echo "$$out" | awk -v p=$$port -v ip=$(BIND_IP) '{print "  "ip":"p" pid="$$2" "$$1}'; fi; \
	done

wine: isolate-require
	@test -x "$(WINE)" || (echo "[wine] $(WINE) not found"; exit 1)
	@test -f "$(CLIENT_DIR)/$(CLIENT_EXE)" || (echo "[wine] missing $(CLIENT_DIR)/$(CLIENT_EXE) — run 'make vendor-client'"; exit 1)
	cd $(CLIENT_DIR) && WINEPREFIX=$(WINEPREFIX) WINEDLLOVERRIDES="version=n" \
	  WINEDEBUG=-d3d \
	  $(WINE) $(CLIENT_EXE) -I $(BIND_IP) -ID $(TOKEN) &

# Wine's gcenx-stable on Apple Silicon defaults to OpenGL core profile,
# but XenClient is Direct3D 8/9 era and expects compatibility profile.
# Cap MaxVersionGL at GL 2.x (0x00020000 = major=2 minor=0) so wine
# selects a compat-only context. One-shot — wineprefix-persistent.
gl-compat:
	@$(WINE) reg ADD "HKCU\\Software\\Wine\\Direct3D" /v MaxVersionGL /t REG_DWORD /d 0x00020000 /f
	@$(WINE) reg ADD "HKCU\\Software\\Wine\\Direct3D" /v csmt /t REG_DWORD /d 0 /f
	@echo "[gl-compat] Direct3D MaxVersionGL=2.0, csmt=0 — restart wine"

kill: server-stop
	@pkill -f 'XenClient.exe' 2>/dev/null && echo "[kill] XenClient stopped" || true
	@$(WINESERVER) -k 2>/dev/null || true
	@echo "[kill] done"

replay: isolate-require server-bg wine
	@echo "[replay] up. tail -f /tmp/v2_server.log"

# Inject a DLL from $(DLL_DIR) into the running wine client. The Windows-side
# path is resolved at runtime via `winepath -w` so the same DLL_DIR works
# regardless of where wine-replay/ lives on disk.
#
# XenClient.exe is just a launcher; the actual game process is DXRender.exe.
# Override TARGET= if your build uses a different process (e.g. SosClient).
# Usage: make dll-inject DLL=dom_replay.dll [TARGET=DXRender]
TARGET ?= DXRender
dll-inject:
	@test -n "$(DLL)" || (echo "[dll-inject] usage: make dll-inject DLL=<name>.dll"; exit 1)
	@test -f "$(DLL_DIR)/injector.exe" || (echo "[dll-inject] missing $(DLL_DIR)/injector.exe"; exit 1)
	@test -f "$(DLL_DIR)/$(DLL)" || (echo "[dll-inject] missing $(DLL_DIR)/$(DLL)"; exit 1)
	@WIN_PATH=$$(WINEPREFIX=$(WINEPREFIX) $(WINE) winepath -w "$(DLL_DIR)/$(DLL)") && \
	  echo "[dll-inject] DLL=$$WIN_PATH target=$(TARGET)" && \
	  WINEPREFIX=$(WINEPREFIX) $(WINE) "$(DLL_DIR)/injector.exe" "$$WIN_PATH" "$(TARGET)"

# Send a command for dom_replay.dll to consume (probe | pick_slot N | start_game).
# Usage: make dom-cmd CMD='pick_slot 0'
dom-cmd:
	@test -n "$(CMD)" || (echo "[dom-cmd] usage: make dom-cmd CMD='probe' (or 'pick_slot N' / 'start_game')"; exit 1)
	@printf '%s' "$(CMD)" > "$(WINE_C)/dom_cmd.txt"
	@echo "[dom-cmd] wrote to $(WINE_C)/dom_cmd.txt: $(CMD)"

# Drive recorded clicks into the wine'd client via dom_replay.dll. Pure
# file-IPC: writes commands to $(WINE_C)/dom_cmd.txt at recorded inter-event
# timing, DLL polls + dispatches in-process. Mac mouse/keyboard untouched.
#
# Requires: wine running with dom_replay.dll already injected. Use
# `make dll-inject DLL=dom_replay.dll` first, or `make full-replay` for
# the fully-orchestrated flow.
SLOT ?= 0
dll-input:
	@test -n "$(JSONL)" || (echo "[dll-input] no recording — set RECORDING_ID=<id>"; exit 1)
	@test -f "$(JSONL)" || (echo "[dll-input] missing $(JSONL)"; exit 1)
	$(PYTHON) dom_driver.py --recording "$(JSONL)" \
	  --cmd-file "$(WINE_C)/dom_cmd.txt" \
	  --log-file "$(WINE_C)/dom_replay.log" \
	  --speed $(SPEED) --login-slot $(SLOT) \
	  $(if $(SKIP_LOGIN),--skip-login,) \
	  $(if $(DRY_RUN),--dry-run,)

# End-to-end (LEGACY, injection-based): only works on wine builds where
# CreateRemoteThread doesn't corrupt wow64 process state. Wine 10.0 doesn't
# qualify — use full-replay-hijack instead.
INJECT_DELAY ?= 5
full-replay: isolate-require server-bg wine
	@echo "[full-replay] sleeping $(INJECT_DELAY)s for DXRender to finish init, then injecting"
	@sleep $(INJECT_DELAY)
	@$(MAKE) --no-print-directory dll-inject DLL=dom_replay.dll
	@$(MAKE) --no-print-directory dll-input

# ---------------------------------------------------------------------------
# DLL-hijack path (the one that actually works under Wine 10 wow64).
#
# DXRender.exe imports VerQueryValueA / GetFileVersionInfoSizeA /
# GetFileVersionInfoA from version.dll. Wine's loader searches the EXE's
# directory BEFORE system32 for imported DLLs, so dropping our own
# version.dll into client/ makes it the one DXRender loads — at process
# startup, by the natural import-resolution path, with no remote thread.
#
# Our version.dll: forwards the 3 exports to the real system32 version.dll
# (via LOAD_LIBRARY_SEARCH_SYSTEM32 to bypass our hijack), and side-loads
# sibling dom_replay.dll so its DllMain can spin up the polling thread.

CLIENT_VERSION_DLL := $(CLIENT_DIR)/version.dll
CLIENT_DOM_DLL     := $(CLIENT_DIR)/dom_replay.dll

hijack-build:
	@echo "[hijack-build] $(MAKE) -C dll version.dll dom_replay.dll"
	@$(MAKE) --no-print-directory -C $(DLL_DIR) version.dll dom_replay.dll

hijack-install: hijack-build
	@test -d "$(CLIENT_DIR)" || (echo "[hijack-install] $(CLIENT_DIR) missing — run 'make vendor-client'"; exit 1)
	@echo "[hijack-install] copying version.dll + dom_replay.dll into $(CLIENT_DIR)"
	cp "$(DLL_DIR)/version.dll"     "$(CLIENT_VERSION_DLL)"
	cp "$(DLL_DIR)/dom_replay.dll"  "$(CLIENT_DOM_DLL)"
	@ls -la "$(CLIENT_VERSION_DLL)" "$(CLIENT_DOM_DLL)"

hijack-uninstall:
	@rm -f "$(CLIENT_VERSION_DLL)" "$(CLIENT_DOM_DLL)"
	@echo "[hijack-uninstall] removed."

# Like full-replay but uses the DLL hijack. version.dll already in client/
# means DXRender loads dom_replay.dll itself at startup — no injector,
# no CreateRemoteThread, no wow64 crash. Driver only handles command
# pacing once the game reaches CharSelect.
full-replay-hijack: isolate-require hijack-install server-bg wine
	@echo "[full-replay-hijack] DLL hijacked; game loads dom_replay.dll natively at startup"
	@$(MAKE) --no-print-directory dll-input

# Same end-to-end but skips the runtime isolate-require gate. Use when
# the pf anchor is permanently installed (via 'make setup-isolate') and
# you don't want each replay to require a fresh `sudo -v`. Trust the
# install — we won't double-check. Bypasses the wine target's gate too
# by inlining its body directly.
WINE_BG_LOG ?= /tmp/wine-launch.log
DRIVER_LOG  ?= /tmp/driver.log
SERVER_LOG  ?= /tmp/v2_server.log

replay-go: hijack-install
	@test -f "$(JSONL)" || (echo "[replay-go] no recording — set RECORDING_ID=<id>"; exit 1)
	@echo "[replay-go] killing stale processes"
	@pkill -9 -f 'dom_driver|DXRender|XenClient|v2_server' 2>/dev/null || true
	@$(WINESERVER) -k 2>/dev/null || true
	@sleep 2
	@echo "[replay-go] starting v2_server (recording=$(notdir $(JSONL)) bind=$(BIND_IP))"
	@nohup $(PYTHON) -u v2_server.py "$(JSONL)" \
	  --bind $(BIND_IP) --rewrite-host $(BIND_IP) --speed $(SPEED) \
	  --world-lookahead-seq 999999 --world-gate-timeout-s 0.5 \
	  $(SWAP_FLAG) > $(SERVER_LOG) 2>&1 &
	@sleep 1
	@echo "[replay-go] launching wine ($(WINE) $(CLIENT_EXE) -I $(BIND_IP))"
	@( cd $(CLIENT_DIR) && WINEPREFIX=$(WINEPREFIX) WINEDLLOVERRIDES="version=n" \
	  nohup $(WINE) $(CLIENT_EXE) -I $(BIND_IP) -ID $(TOKEN) \
	  > $(WINE_BG_LOG) 2>&1 & )
	@echo "[replay-go] sleeping 12s for wine + DLL attach"
	@sleep 12
	@echo "[replay-go] starting driver (RECORDING_ID=$(RECORDING_ID))"
	@nohup $(PYTHON) -u dom_driver.py --recording "$(JSONL)" \
	  --start-delay 0 --match-timeout 8 --login-slot $(SLOT) \
	  $(if $(SKIP_LOGIN),--skip-login,) \
	  > $(DRIVER_LOG) 2>&1 &
	@sleep 0.3
	@echo ""
	@echo "[replay-go] running. Tail logs:"
	@echo "    tail -f $(DRIVER_LOG)            # click pacing + sync status"
	@echo "    tail -f $(SERVER_LOG)            # packet matches + world burst"
	@echo "    tail -f ~/.wine/dosdevices/c\\:/dom_replay.log  # DLL command acks"
	@echo "Stop with: make kill"

# Live diagnostic: ask the DLL to enumerate every known form's live
# instances. Useful when full-replay times out — tells you whether the
# game is stuck on server-select, char-select, or already in-world.
# Requires dom_replay.dll already injected.
scan:
	@printf '%s' "scan #$$(date +%s)" > "$(WINE_C)/dom_cmd.txt"
	@sleep 2
	@echo "[scan] last 25 lines of dom_replay.log:"
	@tail -25 "$(WINE_C)/dom_replay.log" 2>/dev/null || echo "  (no log yet — DLL may not be injected)"

# Diagnostic: ask the DLL to enumerate every visible window of the game
# process (top-level + children). Use to discover the canvas hwnd that
# clicks should target — particularly when PostMessage to the auto-picked
# window doesn't visibly do anything.
windows:
	@printf '%s' "enum_windows #$$(date +%s)" > "$(WINE_C)/dom_cmd.txt"
	@sleep 1
	@echo "[windows] last 40 lines of dom_replay.log:"
	@tail -40 "$(WINE_C)/dom_replay.log" 2>/dev/null || echo "  (no log yet)"

# Recorded prod IP — extracted from sessions/recording_*.jsonl server_endpoint
# events. Hard-blocked at the OS via pf so neither v2_server nor wine'd
# XenClient can reach it even if some hardcoded fallback path tries.
PROD_IP ?= 70.35.198.73

isolate-help:
	@echo "Isolation install (one-time):"
	@echo "  1. Add to /etc/pf.conf (just before any final 'anchor' lines):"
	@echo "       anchor \"wine-replay\""
	@echo "       load anchor \"wine-replay\" from \"$(realpath isolation/pf-wine-replay.conf)\""
	@echo "  2. sudo pfctl -E -f /etc/pf.conf"
	@echo ""
	@echo "Verify:    make isolate-status"
	@echo "Test:      make isolate-test    # tries to reach $(PROD_IP):1818, expects timeout"

isolate-status:
	@echo "[pf] enable state:"; sudo pfctl -s info 2>/dev/null | grep -E 'Status|Debug' || echo "  (need sudo)"
	@echo "[pf] wine-replay anchor rules:"; sudo pfctl -a wine-replay -s rules 2>/dev/null || echo "  (anchor not loaded — run 'make isolate-help')"

isolate-test:
	@echo "[isolate-test] attempting TCP $(PROD_IP):1818 (5s connect timeout) — expect failure"
	@nc -v -G 5 -w 5 -z $(PROD_IP) 1818 && echo "[isolate-test] WARN: connection succeeded — pf rule NOT active" || echo "[isolate-test] OK: blocked"

# Hard gate that all wine launches must pass through. Fails (and aborts the
# parent target) if the pf anchor isn't loaded with the prod-IP block.
isolate-require:
	@sudo -n pfctl -a wine-replay -s rules 2>/dev/null | grep -q "block drop out quick.*$(PROD_IP)" \
	  || (echo "[isolate-require] FAIL: pf anchor 'wine-replay' missing block on $(PROD_IP)."; \
	      echo "  Install with: make isolate-help"; \
	      echo "  (Requires sudoers NOPASSWD for 'pfctl -a wine-replay -s rules', or run 'sudo -v' first.)"; \
	      exit 1)
	@echo "[isolate-require] OK: pf anchor blocking $(PROD_IP)"

# Pull the live game install into ./client/ so wine-replay/ is self-serving.
# Uses rsync so it's restartable. ~2.5GB; gitignored.
vendor-client:
	@test -d "$(SRC_CLIENT)" || (echo "[vendor-client] missing $(SRC_CLIENT)"; exit 1)
	@test -f "$(SRC_CLIENT)/$(CLIENT_EXE)" || (echo "[vendor-client] $(SRC_CLIENT)/$(CLIENT_EXE) not found"; exit 1)
	@mkdir -p $(CLIENT_DIR)
	@echo "[vendor-client] rsync $(SRC_CLIENT)/ -> $(CLIENT_DIR)/  (this can take a few minutes)"
	rsync -a --info=progress2 "$(SRC_CLIENT)/" "$(CLIENT_DIR)/"
	@echo "[vendor-client] done."

vendor-status:
	@if [ -f "$(CLIENT_DIR)/$(CLIENT_EXE)" ]; then \
	  echo "[vendor-status] client OK: $(CLIENT_DIR)/$(CLIENT_EXE) ($$(du -sh $(CLIENT_DIR) | cut -f1))"; \
	else \
	  echo "[vendor-status] client NOT vendored — run 'make vendor-client'"; \
	fi
	@if [ -f "$(DLL_DIR)/injector.exe" ] && [ -f "$(DLL_DIR)/dom_replay.dll" ]; then \
	  echo "[vendor-status] dll  OK: $(DLL_DIR) ($$(du -sh $(DLL_DIR) | cut -f1))"; \
	else \
	  echo "[vendor-status] dll  MISSING — re-copy from ~/proj/tools/dll"; \
	fi

# ---------------------------------------------------------------------------
# Fresh-Mac bootstrap. Run once on a new machine after copying wine-replay/
# (with vendored client/ + dll/) into place. Will prompt for sudo.
#
#   make setup
#
# Components installed:
#   - LaunchDaemon for loopback aliases 127.0.0.2 + 127.0.0.3 (boot-persistent)
#   - pf anchor that blocks egress to recorded prod IP $(PROD_IP)
#
# Components verified (not auto-installed — hands-off if you've already got
# them, instructions printed if missing):
#   - python3, wine, $(WINEPREFIX)
#   - vendored ./client and ./dll
#
# Idempotent: safe to re-run.

LOOPBACK_PLIST_SRC := $(CURDIR)/isolation/com.local.loopback-alias.plist
LOOPBACK_PLIST_DST := /Library/LaunchDaemons/com.local.loopback-alias.plist
PF_ANCHOR_PATH     := $(CURDIR)/isolation/pf-wine-replay.conf
PF_CONF_MARKER     := \# wine-replay isolation (managed by wine-replay/Makefile)

setup: setup-deps setup-loopback setup-isolate setup-verify
	@echo ""
	@echo "[setup] complete. To replay:"
	@echo "  sudo -v                     # prime sudo cache (5min)"
	@echo "  make replay RECORDING_ID=<id>"

setup-deps:
	@echo "[setup-deps] checking host requirements"
	@command -v python3 >/dev/null || (echo "  FAIL: python3 not found"; exit 1)
	@echo "  python3:    $$(command -v python3)"
	@command -v $(WINE) >/dev/null 2>&1 || command -v wine >/dev/null 2>&1 || \
	  (echo "  FAIL: wine not found at $(WINE) or in PATH."; \
	   echo "        Install via Homebrew: brew install --cask --no-quarantine gcenx/wine/wine-stable"; \
	   echo "        (or Whisky / GPTK / CrossOver — set WINE=<path> when invoking make)"; \
	   exit 1)
	@echo "  wine:       $(WINE)"
	@test -d "$(WINEPREFIX)" || (echo "  WARN: WINEPREFIX $(WINEPREFIX) does not exist."; \
	   echo "        It will be auto-created on first wine launch.")
	@test -d "$(WINEPREFIX)" && echo "  wineprefix: $(WINEPREFIX)" || true
	@test -f "$(CLIENT_DIR)/$(CLIENT_EXE)" \
	  || (echo "  FAIL: $(CLIENT_DIR)/$(CLIENT_EXE) missing — vendor a game install before setup."; \
	      echo "        On the source mac: make vendor-client"; \
	      echo "        Or rsync ./client/ from another wine-replay/ folder."; \
	      exit 1)
	@echo "  client:     $(CLIENT_DIR) ($$(du -sh $(CLIENT_DIR) | cut -f1))"
	@test -f "$(DLL_DIR)/injector.exe" && test -f "$(DLL_DIR)/dom_replay.dll" \
	  || (echo "  FAIL: $(DLL_DIR) missing injector.exe or dom_replay.dll"; exit 1)
	@echo "  dll:        $(DLL_DIR)"

# Install LaunchDaemon for loopback aliases 127.0.0.2 + 127.0.0.3.
# Idempotent: launchctl bootout/load resets to current plist contents.
setup-loopback:
	@echo "[setup-loopback] installing $(LOOPBACK_PLIST_DST)"
	@test -f "$(LOOPBACK_PLIST_SRC)" || (echo "  FAIL: missing $(LOOPBACK_PLIST_SRC)"; exit 1)
	@sudo cp "$(LOOPBACK_PLIST_SRC)" "$(LOOPBACK_PLIST_DST)"
	@sudo chown root:wheel "$(LOOPBACK_PLIST_DST)"
	@sudo chmod 644 "$(LOOPBACK_PLIST_DST)"
	@sudo launchctl bootout system "$(LOOPBACK_PLIST_DST)" 2>/dev/null || true
	@sudo launchctl bootstrap system "$(LOOPBACK_PLIST_DST)"
	@sudo launchctl kickstart -k system/com.local.loopback-alias 2>/dev/null || true
	@sleep 0.5
	@echo "[setup-loopback] lo0 aliases:"
	@ifconfig lo0 | awk '/inet 127/ {print "    "$$0}'

# Install pf anchor referencing this folder's $(PF_ANCHOR_PATH). Edits
# /etc/pf.conf in-place (with timestamped backup) and reloads pf.
# Idempotent: skipped if anchor already present, even from a different folder.
setup-isolate:
	@echo "[setup-isolate] installing pf anchor for $(PROD_IP)"
	@test -f "$(PF_ANCHOR_PATH)" || (echo "  FAIL: missing $(PF_ANCHOR_PATH)"; exit 1)
	@if sudo grep -q '^anchor "wine-replay"' /etc/pf.conf 2>/dev/null; then \
	  echo "  /etc/pf.conf already references anchor wine-replay — leaving as-is."; \
	  echo "  (If the load path is stale, edit /etc/pf.conf manually.)"; \
	else \
	  echo "  appending anchor + load lines to /etc/pf.conf"; \
	  sudo cp /etc/pf.conf /etc/pf.conf.bak.$$(date +%s); \
	  printf '\n%s\nanchor "wine-replay"\nload anchor "wine-replay" from "%s"\n' \
	    '$(PF_CONF_MARKER)' '$(PF_ANCHOR_PATH)' \
	    | sudo tee -a /etc/pf.conf >/dev/null; \
	fi
	@echo "  reloading pf"
	@sudo pfctl -E -f /etc/pf.conf 2>&1 | grep -v 'pf already enabled' || true
	@echo "[setup-isolate] anchor rules now active:"
	@sudo pfctl -a wine-replay -s rules 2>/dev/null | sed 's/^/    /'

setup-verify:
	@echo "[setup-verify] running checks (priming sudo cache)"
	@sudo -v
	@printf "  loopback 127.0.0.3:    "; ifconfig lo0 | grep -q '127.0.0.3' && echo OK || echo MISSING
	@printf "  pf anchor wine-replay: "; sudo pfctl -a wine-replay -s rules 2>/dev/null | grep -q "$(PROD_IP)" && echo OK || echo MISSING
	@printf "  prod-IP block test:    "; nc -G 5 -w 5 -z $(PROD_IP) 1818 >/dev/null 2>&1 && echo "FAIL (connection succeeded)" || echo "OK (timed out)"
	@printf "  client vendored:       "; test -f "$(CLIENT_DIR)/$(CLIENT_EXE)" && echo OK || echo MISSING
	@printf "  dll vendored:          "; test -f "$(DLL_DIR)/injector.exe" -a -f "$(DLL_DIR)/dom_replay.dll" && echo OK || echo MISSING

# Reverse setup-loopback + setup-isolate. Leaves vendored client/ and dll/
# alone (delete those manually if you want).
setup-uninstall:
	@echo "[setup-uninstall] removing pf anchor reference from /etc/pf.conf"
	@if sudo grep -q '^anchor "wine-replay"' /etc/pf.conf 2>/dev/null; then \
	  sudo cp /etc/pf.conf /etc/pf.conf.bak.$$(date +%s); \
	  sudo sed -i '' -e '/wine-replay isolation/,/^load anchor "wine-replay"/d' /etc/pf.conf; \
	  sudo pfctl -f /etc/pf.conf 2>&1 | grep -v 'pf already enabled' || true; \
	  echo "  removed."; \
	else \
	  echo "  no anchor present."; \
	fi
	@echo "[setup-uninstall] removing LaunchDaemon $(LOOPBACK_PLIST_DST)"
	@if [ -f "$(LOOPBACK_PLIST_DST)" ]; then \
	  sudo launchctl bootout system "$(LOOPBACK_PLIST_DST)" 2>/dev/null || true; \
	  sudo rm -f "$(LOOPBACK_PLIST_DST)"; \
	  echo "  removed (loopback aliases will disappear on next reboot)."; \
	else \
	  echo "  not installed."; \
	fi
