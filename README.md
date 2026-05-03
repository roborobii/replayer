# replayer

Record a VM game session on a Windows host (passive, undetectable to the
live fan-server), then replay it offline against the same game client
running on a separate offline Windows machine. Mac orchestrates both
ends; never installs on or reaches the live server.

`recorder/` and `replay/` will appear at the top level when v2 lands.

## Status

- v1 cherry-picked into `archive/`. The recording at
  `archive/captures/phase3_walk_v4.jsonl` replays end-to-end via the v1
  flow (DLL injection + docker stub).
- v2 design locked. Build tomorrow.

## v2 plan

### Three-machine layout

| Machine | Role | Network |
|---|---|---|
| **Mac** (`192.168.12.148`) | Orchestrator. Holds JSONL recordings, the replayer, the cipher logic. | Internet + LAN |
| **NVIDIA HOST** (`RC@192.168.12.196`) | Recording host. Runs Hyper-V VM "Elf"; the game client inside the VM connects to the live fan-server. | Internet |
| **Offline RC3** (`RC3@192.168.12.188`) | Replay-only target. ThinkPad T470, no internet, can only reach Mac. SSH/SCP via `~/.ssh/xen_win_ed25519`. | Outbound to Mac only |

### Recording (NVIDIA HOST, undetectable to live server)

VM "Elf" pinned to **1440x900** basic-session (`Set-VMVideo`). DXRender
**fullscreen inside the VM** — VM-screen coords map directly to game-UI
coords with no per-event window math.

```
host-record-v2.ps1
  ├── tshark #1 (raw all-VM TCP) ──► recording_<id>.pcap
  └── python host_recording_stream_v2.py
        ├── net-sniffer thread     (tshark #2 on game ports, V2-decoded)
        └── input-recorder thread  (WH_MOUSE_LL + WH_KEYBOARD_LL,
                                    foreground-filtered to vmconnect HWND)
              │
              ▼
        JsonlWriter (mutex; seq + t_mono_ns + t_wall_ns at capture)
              │
              ▼
        recording_<id>.jsonl
        recording_<id>.manifest.json
```

Reuse: `archive/recorder/notes/input-agent/host_agent.py` already
implements the LL hook + foreground filter + fractional-coord JSONL
emission. Lift it into the v2 input thread.

**No MemProcFS.** Form-poller is dropped, no memory deltas, so
`hvmm.sys` is never loaded; BSOD root cause is structurally absent.

**Stealth surface:**
- *Network* — `tshark` on host vEthernet, passive sniff (proven
  invisible to live server in v1).
- *Input* — host-side LL hooks observe events *before* they cross
  VMBus into the guest. The guest OS / game client / live server
  cannot enumerate or detect host-side hooks. Same architectural
  mechanism EDR products use; not detectable to in-guest userland.

### Replay (Mac orchestrates, RC3 runs the game)

```
                              LAN
   MAC (.148)                                       RC3 (.188, offline)
   ──────────                                       ────────────────────
   replayer.py                                      XenClient.exe
     binds .148:1818/1819/                          (windowed @ 1440x900,
            18123/18124        ◄────────────────── -i 192.168.12.148)
     reads recording.jsonl       game protocol         │ same client binary
     pair-match C2S → recorded S2C                     │ as recording
     V2 encrypt for live K2                            │
     synth input events  ────────────────────────► helper.ps1
                            input cmd socket          listens .188:19999
                                                      PostMessage(xen_hwnd,
                                                        WM_LBUTTONDOWN, ...)
                                                      (no cursor takeover)
```

**Why RC3, not Wine on Mac:** keeps Mac input untouched. PostMessage
delivers events to a specific HWND, so RC3's cursor doesn't move and
no other RC3 app sees anything. XenClient receives clicks at recorded
`(cx, cy)` regardless of where its window sits on the desktop.

**Resolution:** XenClient on RC3 windowed at 1440x900 (matching the
recording VM). Recorded coords map 1:1, no scaling math. RC3's
1920x1080 panel has room to spare.

**Helper on RC3** — single PowerShell file, ~80 lines:
- `[System.Net.Sockets.TcpListener]` on `.188:19999`
- `Add-Type` P/Invoke for `user32.dll` (`FindWindow`, `PostMessage`)
- Newline-delimited JSON commands → `PostMessage` calls
- `SendInput` fallback if any DirectInput path surfaces (user reports
  no camera-drag in their typical sessions, so unlikely needed)

**Channels:**

| Channel | Direction | Transport |
|---|---|---|
| Game protocol | RC3 → Mac | TCP on game ports (Mac binds, RC3 connects) |
| Input commands | Mac → RC3 | TCP socket `.188:19999` |
| Orchestration | Mac → RC3 | SSH (`xen_win_ed25519`); one-time SCP for helper |

### Output bundle (3 files per session)

```
recording_<id>.pcap          # raw all-VM TCP, safety net
recording_<id>.jsonl         # net + input events on unified timeline
recording_<id>.manifest.json # client SHA, vm_res, schema, start/exit
```

### JSONL event kinds

Universal fields on every event: `kind`, `seq`, `t_mono_ns`, `t_wall_ns`.
`seq` is allocated under the `JsonlWriter` mutex at the moment of
capture → total ordering across threads.

| `kind` | Source | Notes |
|---|---|---|
| `session_start` / `session_stop` | recorder lifecycle | manifest fields included |
| `viewport` | session start + on resize | `(client_w, client_h, vm_res, vmconnect_hwnd, dpi)` |
| `net` | net-sniffer | port, dir (`c2s`/`s2c`), opcode, subop, `payload_hex`, `decrypted` |
| `server_endpoint` | first-IP-seen detection | `(ip, port)` |
| `input_mouse_move` | LL mouse hook (downsampled ~60 Hz) | `(cx, cy, cw, ch)` |
| `input_mouse_button` | LL mouse hook | `button`, `event` (`down`/`up`), `cx,cy,cw,ch`, `mods[]` |
| `input_mouse_wheel` | LL mouse hook | `delta` |
| `input_key` | LL keyboard hook | `event`, `vk`, `vk_name`, `scan`, `mods[]`, `repeat` |
| `input_focus` | window event | `focused:bool` — replay pauses synth on `false` |

### Build phases

**Phase A — replayer on Mac, consumes existing v1 JSONL.**

- Read `~/proj/server-emulator-python3/` pair-matcher → port matching
  algorithm into `replay/replayer.py`
- Add V2 cipher encrypt direction to `archive/recorder/v2cipher.py`
  (lift to `replay/v2cipher.py`)
- TCP listeners on game ports
- **Win condition:** `archive/captures/phase3_walk_v4.jsonl` replays
  end-to-end through new replayer + XenClient on RC3 + `helper.ps1`.
  No docker, no DLL injection.

**Phase B — recorder v2 produces v2 JSONL shape.**

- Build `recorder/host_recording_stream_v2.py`:
  - net-sniffer (lift from v1, no concept changes)
  - input-recorder (lift from `archive/recorder/notes/input-agent/host_agent.py`,
    integrate into JsonlWriter)
  - Drop form-poller entirely
- New launcher `recorder/host-record-v2.ps1`
- Manifest emission at session start
- **Win condition:** a fresh v2 recording plays back through Phase A.

### What got dropped from earlier iterations

| Dropped | Why |
|---|---|
| Form-poller | Input replay drives form interactions naturally |
| Memory baseline + deltas (`baseline.zst`, `mem.delta.zst`) | Replay reconstructs memory state by feeding same client user inputs and same network packets; ad-hoc MemProcFS attach to replay's XenClient covers RE inspection on demand |
| `--bsod-safe` toggle | No `hvmm.sys` ever loads in v2 recorder, so the bug surface is gone |
| MemProcFS dependency in recorder | None of the v2 threads need `M:\` |
| All-forms full-instance recorder | Corollary of dropping form-poller |
| Filesystem capture | Out of scope, offline game client captures this |
| Audio | Out of scope, offline game client captures this |
| Wine-on-Mac for replay | RC3 runs real Windows; no Mac takeover |
| DLL injection during replay | PostMessage to HWND avoids it |
| Sync beacon for pcap↔JSONL alignment | Both QPC-aligned via Npcap + Python `time.monotonic_ns`; adequate to ~µs |

### Decisions locked in

- Read-first for archived V1 `host_agent.py` (recorder side) and the docker
  stub's pair-matcher (replayer side)
- Pin XenClient window to 1440x900 on RC3 (1:1 coord mapping)
- No camera-drag input — PostMessage path is sufficient
- PowerShell helper on RC3 (no compilation, easy iteration,
  scp-deployable as a single file)
- Single TCP socket for input commands (`.188:19999`); persistent
  connection, JSON lines
