# replayer

Record a VM game session on a Windows host (passive, undetectable to
the live fan-server), then replay it offline on a separate offline
Windows machine. Mac orchestrates over SSH/SCP; never reaches the
live server.

`recorder/` and `replay/` will appear at the top level when v2 lands;
`archive/` holds frozen v1 reference.

## Status

- v1 cherry-picked into `archive/`. `archive/captures/phase3_walk_v4.jsonl`
  replays end-to-end via the v1 flow (DLL injection + docker stub).
- v2 design locked. Build next.

## Three-machine layout

| Machine | Role | Network |
|---|---|---|
| **Mac** (`192.168.12.148`) | Stores recordings. SSH/SCP-orchestrates the replay session. Idle during replay itself. | Internet + LAN |
| **NVIDIA HOST** (`RC@192.168.12.196`) | Recording host. Hyper-V VM "Elf" runs the game client against the live fan-server. | Internet |
| **Offline RC3** (`RC3@192.168.12.188`) | Self-contained replay target. T470, no internet, can only reach Mac. Runs replayer + XenClient locally; all loopback. | Outbound to Mac only |

## Recording (NVIDIA HOST, undetectable to live server)

VM "Elf" pinned to **1440x900** basic session (`Set-VMVideo`).
DXRender **fullscreen inside the VM** — VM-screen coords = game-UI
coords with no per-event window math.

```
host-record-v2.ps1
  ├── tshark #1 (raw all-VM TCP) ──► recording_<id>.pcap
  └── python host_recording_stream_v2.py
        ├── net-sniffer thread     (tshark #2 on game ports, V2-decoded)
        └── input-recorder thread  (WH_MOUSE_LL + WH_KEYBOARD_LL,
                                    foreground-filtered to vmconnect)
              │
              ▼
        JsonlWriter (mutex; seq + t_mono_ns + t_wall_ns at capture)
              │
              ▼
        recording_<id>.jsonl
        recording_<id>.manifest.json
```

Reuse `archive/input-agent/host_agent.py` for the input thread (LL
hooks + vmconnect foreground filter + JSONL emit, already implemented).

**No MemProcFS, no `hvmm.sys`** — form-poller and memory deltas are
both dropped. BSOD root cause is structurally absent.

**Stealth surface:**
- *Network* — `tshark` on host vEthernet, passive sniff (proven in v1).
- *Input* — host-side LL hooks observe events *before* they cross
  VMBus into the guest. Guest OS / game / live server cannot enumerate
  them. Same mechanism EDR products use.

## Replay (RC3 self-contained)

```
                  SSH / SCP
   MAC (.148) ──────────────────►  RC3 (.188, offline)
                                   ──────────────────────
   stores recording bundles        replayer.py (one process):
                                     ├── reads recording.jsonl
   one-time:                         ├── binds 127.0.0.1:1818/1819/
     scp replayer.py → RC3           │       18123/18124 (loopback)
     scp recording → RC3             ├── pair-match C2S → recorded S2C
                                     ├── V2 cipher (encrypt for live K2)
   per session:                      └── input synth via ctypes
     ssh: launch replayer.py             PostMessage to XenClient HWND
     ssh: launch XenClient                  ▲       │
     wait                                   │       │ loopback
     ssh: cleanup                           │       ▼
                                       XenClient.exe (windowed @ 1440x900,
                                                     -i 127.0.0.1)
```

**Why this shape:**
- Loopback-only game protocol — sub-µs latency, no LAN dependency
- One Python process owns TCP servers + cipher + pair-matcher + input synth
- Mac can be powered off after launching
- `PostMessage` to a specific HWND → no cursor takeover anywhere
- XenClient at 1440x900 windowed = 1:1 coord mapping with the recorded VM

## Output bundle (3 files per session)

```
recording_<id>.pcap          # raw all-VM TCP, safety net
recording_<id>.jsonl         # net + input events on unified timeline
recording_<id>.manifest.json # client SHA, vm_res, schema, start/exit
```

## JSONL event kinds

Universal fields on every event: `kind`, `seq`, `t_mono_ns`, `t_wall_ns`.
`seq` is allocated under the JsonlWriter mutex at capture → total
ordering across threads.

| `kind` | Source | Notes |
|---|---|---|
| `session_start` / `session_stop` | recorder lifecycle | manifest fields included |
| `viewport` | session start + on resize | `(client_w, client_h, vm_res, vmconnect_hwnd, dpi)` |
| `net` | net-sniffer | `port, dir, opcode, subop, payload_hex, decrypted` |
| `server_endpoint` | first-IP-seen detection | `(ip, port)` |
| `input_mouse_move` | LL mouse hook (~60 Hz) | `(cx, cy, cw, ch)` |
| `input_mouse_button` | LL mouse hook | `button, event, cx, cy, cw, ch, mods` |
| `input_mouse_wheel` | LL mouse hook | `delta` |
| `input_key` | LL keyboard hook | `event, vk, vk_name, scan, mods, repeat` |
| `input_focus` | window event | `focused:bool` — replay pauses synth on `false` |

## Build phases (parallelizable)

**Phase A — replayer on RC3, consumes existing v1 JSONL.**

- Port pair-matcher from `~/proj/server-emulator-python3/`
- Add V2 cipher encrypt direction (lift from `archive/recorder/v2cipher.py`)
- `asyncio` TCP listeners on `127.0.0.1:1818/1819/18123/18124`
- `ctypes` for `FindWindow` + `PostMessage` (in-process, no helper)
- Mac-side `replay.sh` does SCP + SSH-launch + cleanup
- **Win:** `archive/captures/phase3_walk_v4.jsonl` replays end-to-end on RC3.

**Phase B — recorder v2 produces v2 JSONL.**

- `recorder/host_recording_stream_v2.py`:
  - net-sniffer (lift from v1 conceptually)
  - input-recorder (lift `archive/input-agent/host_agent.py` into JsonlWriter)
  - drop form-poller
- New launcher `recorder/host-record-v2.ps1`
- Manifest emission at session start
- **Win:** fresh v2 recording plays back through Phase A.

Phase A and B are independent — share only the JSONL schema as their
contract. Build via parallel Opus subagents.

## What got dropped

| Dropped | Why |
|---|---|
| Form-poller | Input replay drives form interactions naturally |
| Memory baseline + deltas | Replay reconstructs memory via same client + same packets; ad-hoc MemProcFS attach to replay's XenClient covers RE inspection |
| `--bsod-safe` toggle | No `hvmm.sys` ever loads in v2 |
| MemProcFS in recorder | None of v2's threads need `M:\` |
| Wine-on-Mac for replay | Real Windows on RC3; no Mac takeover |
| DLL injection at replay | `PostMessage` to HWND avoids it |
| Sync beacon | QPC alignment is adequate to ~µs |

## Tomorrow's first actions

1. Read `~/proj/server-emulator-python3/` pair-matcher
2. Confirm Phase A test surface (`archive/captures/phase3_walk_v4.jsonl`)
3. Spin Phase A + B agents in parallel with this README as their contract
