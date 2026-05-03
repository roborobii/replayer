# replayer

Record a Windows game session passively, replay it offline on a sandboxed Windows box. The real game server never sees the replay.

## Three-machine layout

| Machine | Role | Address |
|---|---|---|
| **RC** | Records the live session | `RC@192.168.12.196` |
| **Mac** | Orchestrator + replay packet server | `192.168.12.148` |
| **RC3** | Sandboxed replay client (offline) | `RC3@192.168.12.188` |

RC has internet and runs the legitimate client. RC3 has no internet — its `hosts` file blackholes prod domains to the Mac. Mac's `hosts` 0.0.0.0-blackholes the same domains. The only outbound socket in the replay path goes to the Mac's ctrl-bus on `:18999`.

## Flow

```
1. Record on RC          host-record-v2.ps1  → C:/Users/RC/sessions/recording_<id>.{jsonl,manifest.json,pcap}
2. Pull to Mac           make pull-sessions RECORDING_ID=<id>
3. Replay on RC3         make kill && make auto-replay RECORDING_ID=<id>
```

`auto-replay` runs end-to-end: tears down any prior state, scp's the recording + replay scripts to RC3, starts the Mac's `v2_server.py`, launches XenClient on RC3 pointed at the Mac, resizes the window to 1440×900, and dispatches the recorded clicks/keys against it.

## Architecture

```
RC3 (sandboxed)                              Mac
─────────────────────                        ──────────────────────────────
XenClient.exe -I MAC_IP   ◄── 1818/1819 ──►  v2_server.py (paced S2C feeder)
                          ◄── 18123/18124 ─►   reads recording_<id>.jsonl
                                                rewrites prod IPs in payloads
input_replayer.py                               serves recorded packets at
  reads recording.jsonl  ◄── ctrl-bus 18999 ── recorded t_mono_ns rate
  fires SendInput clicks ─────────────────►
  honors recorded inter-event timing
```

**Mac (`replay/v2_server.py`)** binds 1818/1819/18123/18124, accepts the rewritten client connection, and feeds back recorded S2C frames paced against `t_mono_ns` so in-world animation runs at recorded speed. `--no-pace` disables for fast iteration.

**RC3 (`replay/input_replayer.py`)** finds the XenClient HWND (skips invisible/iconic/0×0 candidates with retry), maps each recorded `(fx, fy)` click fraction to screen coordinates, and dispatches via `SendInput` honoring recorded inter-event timing. Spawn coords parsed from the recording assert against the live spawn frame on world entry.

## Bundle (per recording)

```
recording_<id>.jsonl          # net + input events, seq-ordered, t_mono_ns timestamps
recording_<id>.manifest.json  # vm_res, client_sha, recorded_spawn (when present)
recording_<id>.pcap           # raw TCP, safety net
```

JSONL event kinds: `session_start`/`stop`, `viewport`, `net` (with `port,dir,opcode,payload_hex`), `server_endpoint`, `input_mouse_move`, `input_mouse_button`, `input_mouse_wheel`, `input_key`, `input_focus`.

## Make targets (run from `replay/`)

| Target | Purpose |
|---|---|
| `make list-sessions` | List recordings on RC |
| `make pull-sessions RECORDING_ID=<id>` | scp jsonl + manifest + pcap from RC → `sessions/` |
| `make auto-replay RECORDING_ID=<id>` | Full replay pipeline: deploy + server + client + clicks |
| `make kill` | Full teardown: Mac `v2_server`, RC3 client, scheduled tasks, stale `input_replayer` procs |
| `make server-bg` / `server-stop` | Mac packet server lifecycle (force-frees ports, aborts on bind conflict) |
| `make status` | Show Mac listeners on 1818/1819/18123/18124 |
| `make resize` | Force XenClient window to 1440×900 at (0,0) |
| `make deploy` | scp replay scripts + recording → RC3 (no run) |

Common knobs: `Y_CORRECTION=20` (click vertical offset), `FULLSCREEN=0` (windowed mode), `CLICK_MODE=sendinput|postmessage`.

## Stealth

- **Recording** uses host-side low-level hooks + `tshark` on the VM's vEthernet — passive observation only. The guest OS, the game, and the live server cannot enumerate the hooks.
- **Replay** never reaches the live server. Prod IPs embedded in recorded payloads are rewritten to `MAC_IP` by `rewrite_payload` before being sent to the client (`replay/v2_server.py:164-185`). RC3's hosts file + the explicit `-I MAC_IP` launch arg ensure no DNS or hardcoded fallback path exists.
