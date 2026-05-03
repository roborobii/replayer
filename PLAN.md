# v2 Plan

Final plan for the v2 record + replay pipeline. Build tomorrow.

## Three-machine layout

| Machine | Role | Network |
|---|---|---|
| **Mac** (`192.168.12.148`) | Orchestrator. Holds JSONL recordings, the replayer, the cipher logic. Source of truth at replay time. | Internet + LAN |
| **NVIDIA HOST** (`RC@192.168.12.196`) | Recording host. Runs Hyper-V VM "Elf"; the game client inside the VM connects to the live fan-server. | Internet (so the live game can run) |
| **Offline RC3** (`RC3@192.168.12.188`) | Replay-only target. T470, no internet, can only reach Mac. Mac has SSH/SCP via `~/.ssh/xen_win_ed25519`. | Outbound to Mac only |

## Recording (NVIDIA HOST, undetectable to live server)

**VM config:** "Elf" pinned to **1440x900** basic-session (`Set-VMVideo`). DXRender game client **fullscreen inside the VM** so VM-screen coords = game-UI coords directly, no per-event window-position math.

**Two streams, both passive on the host (above the VM boundary):**

1. **Network** — `tshark` on the host vEthernet adapter. Already proven invisible to the live server in v1.
2. **User input** — `WH_MOUSE_LL` + `WH_KEYBOARD_LL` global hooks installed in a host-side Python recorder. Hooks sit in the host's input chain, observe events *before* they cross VMBus into the guest. The guest OS / game client / live server cannot enumerate or detect host-side hooks.

**Threading model (`host_recording_stream_v2.py`):**

```
host-record-v2.ps1
  ├── tshark #1 (raw all-VM TCP) ──► recording_<id>.pcap
  └── python host_recording_stream_v2.py
        ├── net-sniffer thread     (tshark #2 on game ports, V2-decoded)
        └── input-recorder thread  (LL hooks scoped to vmconnect HWND)
              │
              ▼
        JsonlWriter (mutex; seq + t_mono_ns + t_wall_ns at capture)
              │
              ▼
        recording_<id>.jsonl
        recording_<id>.manifest.json
```

**Reuse:** `recorder/archive/notes/input-agent/host_agent.py` already implements the hook + foreground filter + fractional-coord JSONL emission. Lift it into the v2 input thread.

**No MemProcFS dependency.** The form-poller is dropped, no memory baseline/deltas, so `hvmm.sys` is never loaded. BSOD root cause is structurally absent.

## Replay (Mac orchestrates, RC3 runs the game)

```
                              LAN
   MAC (.148) — orchestrator                       RC3 (.188) — game runner
   ────────────────────────                        ─────────────────────────
   replay/replayer.py                              XenClient.exe
     binds .148:1818/1819/                         (windowed @ 1440x900,
            18123/18124        ◄────────────────── -i 192.168.12.148)
     reads recording.jsonl       game protocol         │
     pair-match C2S → recorded S2C                     │ same client binary
     V2 encrypt for live K2                            │ as recording
     synth input events ─────────────────────────► replay/helper.ps1
                            input cmd socket          listens .188:19999
                                                      PostMessage(xen_hwnd,
                                                        WM_LBUTTONDOWN, ...)
                                                      (no cursor takeover)
```

**Why RC3 not Wine on Mac:** keeps Mac input untouched. PostMessage delivers events to a specific HWND, so RC3's cursor doesn't move and no other RC3 app sees anything. XenClient receives clicks at recorded `(cx, cy)` regardless of where its window sits on the desktop.

**Resolution mapping:** VM is 1440x900, XenClient on RC3 is windowed at 1440x900 — recorded coords map 1:1, no scaling math. RC3's panel is 1920x1080 so a 1440x900 window fits with room to spare.

**Helper on RC3 (PowerShell, single file):**
- `[System.Net.Sockets.TcpListener]` on `.188:19999` for command socket
- `Add-Type` P/Invoke for `user32.dll` (`FindWindow`, `PostMessage`)
- Newline-delimited JSON commands from Mac → translated to `PostMessage`
- `SendInput` fallback if DirectInput-polled paths surface (user reports they don't use camera-drag, so unlikely needed)

**Channels:**

| Channel | Direction | Transport |
|---|---|---|
| Game protocol | RC3 → Mac | TCP on game ports (Mac binds, RC3 connects) |
| Input commands | Mac → RC3 | TCP socket `.188:19999` |
| Orchestration | Mac → RC3 | SSH (`xen_win_ed25519`), SCP for one-time helper deploy |

## Output bundle (3 files per session)

```
recording_<id>.pcap          # raw all-VM TCP, safety net
recording_<id>.jsonl         # net + input events on unified timeline
recording_<id>.manifest.json # client SHA, vm_res, schema, start/exit
```

## JSONL event kinds (v2 schema)

Universal fields on every event: `kind`, `seq`, `t_mono_ns`, `t_wall_ns`. `seq` allocated under `JsonlWriter` mutex at moment of capture → total ordering across threads.

| `kind` | Source | Notes |
|---|---|---|
| `session_start` / `session_stop` | recorder lifecycle | manifest fields included |
| `viewport` | session start + on resize | `(client_w, client_h, vm_res, vmconnect_hwnd, dpi)` |
| `net` | net-sniffer | port, dir (`c2s`/`s2c`), opcode, subop, `payload_hex`, `decrypted` |
| `server_endpoint` | first-IP-seen detection | `(ip, port)` — makes stub setup trivial later |
| `input_mouse_move` | LL mouse hook (downsampled ~60 Hz) | `(cx, cy, cw, ch)` |
| `input_mouse_button` | LL mouse hook | `button`, `event` (`down`/`up`), `cx,cy,cw,ch`, `mods[]` |
| `input_mouse_wheel` | LL mouse hook | `delta` |
| `input_key` | LL keyboard hook | `event`, `vk`, `vk_name`, `scan`, `mods[]`, `repeat` |
| `input_focus` | window event | `focused:bool` — replay pauses synth on `false` |

## Build phases — parallelizable

**Phase A — replayer on Mac, consumes existing v1 JSONL.**

- Read `~/proj/server-emulator-python3/` pair-matcher → port matching algorithm into `replay/replayer.py`
- Add V2 cipher encrypt direction to `recorder/archive/v2cipher.py` (lifting it out of archive into `replay/`)
- TCP listeners on game ports
- **Win condition:** `phase3_walk_v4.jsonl` replays end-to-end through new replayer + XenClient on RC3 + `helper.ps1`. No docker, no DLL injection.

**Phase B — recorder v2 produces v2 JSONL shape.**

- Build `recorder/host_recording_stream_v2.py`:
  - net-sniffer (lift from v1, no changes needed in concept)
  - input-recorder (lift from `archive/notes/input-agent/host_agent.py`, integrate into JsonlWriter)
  - Drop form-poller entirely
- New launcher `recorder/host-record-v2.ps1`
- Manifest emission at session start
- **Win condition:** a fresh v2 recording plays back through the Phase A replayer.

Both phases share the JSONL schema as their contract. They can be developed by parallel Opus subagents — they don't need to see each other's code, only the spec in this file.

## What this plan explicitly drops

| Dropped | Why |
|---|---|
| Form-poller | Input replay drives form interactions naturally |
| Memory baseline + deltas (`baseline.zst`, `mem.delta.zst`) | Replay reconstructs memory state by feeding same client same packets; ad-hoc MemProcFS attach to replay's XenClient covers RE inspection on demand |
| `--bsod-safe` toggle | No `hvmm.sys` ever loads in v2 recorder, so the bug surface is gone |
| MemProcFS dependency in recorder | None of the v2 threads need `M:\` |
| All-forms full-instance recorder (from earlier doc plan) | Corollary of dropping form-poller |
| Filesystem capture | Out of scope, not net or input |
| Audio / screencap | Out of scope, optional |
| Wine-on-Mac for replay | RC3 runs real Windows; cleaner runtime, no Mac takeover |
| DLL injection during replay | PostMessage to HWND avoids it (with SendInput fallback if ever needed for DirectInput paths) |
| Sync beacon for pcap↔JSONL alignment | Both QPC-aligned via Npcap + Python `time.monotonic_ns`; adequate to ~µs |

## Decisions locked in

- **Phase A and Phase B build in parallel** via Opus subagents
- **Read-first** for both `host_agent.py` (recorder side) and the docker stub's pair-matcher (replayer side) — subagents do a read pass, summarize, then implement
- **Pin XenClient window to 1440x900** on RC3 (matches recorded `vm_res`, 1:1 coord mapping)
- **No camera-drag input** in user's typical sessions — PostMessage path is sufficient
- **PowerShell helper on RC3** (no compilation, easy iteration, scp-deployable as single file)
- **Single TCP socket** for input commands (`.188:19999`); persistent connection, JSON lines

## Tomorrow's first actions

1. Pull the docker stub's pair-matcher from `~/proj/server-emulator-python3/` and read it (Phase A subagent's first task)
2. Confirm Phase A test surface: `phase3_walk_v4.jsonl` is in `captures/`; a one-shot script can drive XenClient on RC3 to replay it
3. Spin Phase A and Phase B agents in parallel with this PLAN.md as their shared contract
