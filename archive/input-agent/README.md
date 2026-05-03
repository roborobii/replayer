# Failed Experiment: VM Input Mirror as Sandwich Filling

**Date:** 2026-04-27
**Status:** Abandoned. Code kept dormant for historical reference; defaults off.

## What we wanted

Extend the live shadow mirror (network + memory) with a third layer: capture
mouse/keyboard input from the VM's vmconnect window on the Hyper-V host,
replay it on the offline Wine client running on Mac. Goal was specifically to
open NPC dialog boxes on the offline whenever the user opens them on the VM
— since (per user) the dialog open/close is purely client-side and isn't
broadcast on the wire.

Architectural posture stayed strict: host-side passive observation only,
nothing inside the guest, nothing detectable from the live game server.

## What we built

Two scripts plus a small ingest filter:

- `pipeline/input_capture/host_agent.py` — runs on Windows host in an
  interactive desktop session. Uses pynput's `WH_MOUSE_LL` /
  `WH_KEYBOARD_LL` system-wide hooks, filters events to those where
  `vmconnect.exe` (or `mstsc.exe` for Enhanced Session) is the foreground
  window, normalizes coords to fractions of vmconnect's client area, and
  appends one JSON line per event to a JSONL file.
- `pipeline/input_capture/tail_jsonl.py` — Python-based unbuffered file
  tail that runs on the host. Replaces PowerShell's `Get-Content -Wait`,
  which buffers stdout over SSH and never delivered live lines.
- `pipeline/input_capture/mac_replay.py` — runs on Mac. SSHes to host,
  spawns `tail_jsonl.py`, reads JSONL, scales fractions to the offline
  Wine window, and dispatches each event via the existing
  `tools/click_game.exe` (Win32 `PostMessage` to the Wine HWND).
- `game_server/replay/shadow_ingest.py` — opt-in filter via env vars to
  drop S→C movement broadcasts (`op=0x00/0x01`) for the player's entity
  ID. Goal was to prevent the live server's movement broadcasts from
  fighting click-driven movement on offline. Default OFF.

Wired in `docker-compose.dev.yml` as opt-in env vars:
`SHADOW_BLOCK_PLAYER_MOVE`, `SHADOW_PLAYER_ENTITY_ID`,
`SHADOW_BLOCK_OPCODES`. All default `0` / unset.

## Why it didn't work

Two compounding problems:

1. **Coordinate calibration is multi-stage and fragile.**
   vmconnect window has a top toolbar and possibly letterbox/scaling.
   The Hyper-V guest renders at a fixed res (we tried 1024×768 then
   1280×800) inside vmconnect's variable client area. The offline Wine
   window on Mac has its own outer/client/title-bar geometry. The game
   inside Wine stretches its own canvas to fill Wine's client area.
   Each transition (vmconnect → guest → Wine outer → Wine client →
   game canvas) is a multiplicative scale + offset. Getting them
   exact requires precise corner-click measurements that humans can't
   easily make.

2. **Camera drift between VM and offline.**
   Even with perfect calibration, the same screen-pixel click only maps
   to the same game-world coord *if both clients have their cameras at
   the same world position*. Once we filter the VM's movement broadcasts
   (so the offline doesn't double-move), the offline character is
   driven only by click-replays into the emulator, while the VM character
   moves freely from the live server. The two characters drift apart,
   their cameras follow, and the same vmconnect-pixel click projects to
   different world coords on each side. NPC the user clicked on VM is
   no longer at that screen pixel on offline.

Side issues we hit and fixed but that signal the fragility:
- `WH_MOUSE_LL` doesn't fire from session-0 (SSH-launched Python on
  Windows). Required interactive RDP/desktop session to start the agent.
- PowerShell `Get-Content -Wait` buffers over SSH; bytes were written to
  disk on host but never streamed back. Required custom tail script.
- `Tee-Object` redirected output keeps file handles open in a way that
  prevents `Get-Content -Wait` from seeing appends; required
  per-event open/write/close in the agent.
- vmconnect Enhanced Session blocks display-resolution changes from
  inside the guest ("can't change settings from a remote session"),
  required `Set-VMVideo` while the VM was off, which in turn required
  unmounting `MemProcFS`'s VID partition (memstate POC).

## What we'd do differently

If this were worth retrying:

1. **Sync the offline character's position to the VM's via memory.**
   Read VM's player x,y from memstate at high frequency. Write same
   position to offline emulator's session state, push synthetic move
   broadcasts to offline client. Cameras stay aligned. Click-replay then
   actually lands on the same screen target.

2. **Or skip clicks entirely and synthesize dialog packets.** If a
   network packet for "open NPC dialog X" is ever found (we asserted not,
   but worth re-examining the chat port at 18124), forward those as
   the source of truth and drop input mirror altogether.

3. **Or just let the user click on the offline window directly** when
   live server dies, since by then there's no VM to mirror anyway. The
   shadow mirror is an interim development tool, not a long-term
   end-user feature.

## Code archived here

Everything experiment-specific lives in this folder. The emulator's
`shadow_ingest.py` and `docker-compose.dev.yml` were reverted to their
pre-experiment state — no opt-in filter remains in the live tree.

Files in this folder:

```
failed_experiments/input_mirror/
  README.md                  # this postmortem
  host_agent.py              # Windows host: pynput LL hook + JSONL writer
  tail_jsonl.py              # Windows host: unbuffered file tail (Python)
  mac_replay.py              # Mac: read JSONL via SSH, replay via click_game.exe
  host_input_capture.c       # earlier C-native hook attempt (pre-pynput)
  dialog_state_watch.py      # VM dialog detection via memory marker polling
  dialog_watcher.py          # VM NPC name string-search in heap
  find_cursor.py             # Failed: find cursor coords in DXRender memory
```

To resurrect the experiment (probably don't):

```bash
# Re-add the opt-in filter to game_server/replay/shadow_ingest.py and
# the SHADOW_BLOCK_PLAYER_MOVE env var to docker-compose.dev.yml; both
# can be recovered from git history (commit 039e9d8).
SHADOW_BLOCK_PLAYER_MOVE=1 make dev
# On Windows host (interactive desktop):
&  C:\Users\RC\sessions\start_input_agent.ps1
# On Mac:
python3 failed_experiments/input_mirror/mac_replay.py tail \
  --vmc-rect <rx,ry,rw,rh> --wine-w <W> --wine-h <H>
```
