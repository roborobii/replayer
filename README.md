# replayer

Record a VM game session on the Windows host, replay it offline through
a stub server + Wine client, end-to-end. Stealth boundary: read-only
host-side observation (MemProcFS `M:\`, host-vEthernet tshark, host-side
input hooks) — never any guest hooks, no DLL injection into the guest,
no writes to guest memory. Recording is invisible to the live server
the recorded session was talking to.

## Layout

```
recorder/                                 # host-side recording (deploys to C:\Users\RC\recorder\)
└── archive/                              # v1 — frozen reference, byte-identical to current
    ├── host-record.ps1                   #      Windows deploy. Do not modify; v2 lives
    ├── host_recording_stream.py          #      next to it once written.
    ├── v2cipher.py                       #      world-traffic V2 decryption (imported as
    │                                     #      sibling module by host_recording_stream.py)
    ├── forms_catalog.json                #      Delphi form VMT catalog (default --forms)
    └── onclick_catalog.json              #      form watch-fields + click handlers
                                          #      (default --catalog)

replay/                                   # runs on this Mac
├── recording_replayer.py                 # injects DLL into Wine client, drives form events,
│                                         # gates net to coordinate with stub pair-matcher
└── replay.sh                             # one-shot: tear down Wine → boot stub in PAIR_MATCH
                                          # → launch Wine → run replayer → screenshot

captures/
├── phase3_walk_v4.jsonl                  # proven-good recording (decoded net + form events)
└── phase3_walk_v4.pcap                   # raw all-VM TCP from the same session
```

## What works today (cherry-picked from prior workdir)

`phase3_walk_v4.jsonl` plays back end-to-end via `replay/replay.sh`:
master-server normal handler → SVC pair-matched (D3+D4+D7) → chat
pair-matched (B0) → world cipher pair-matched (LLOGIN + spawn bundle +
in-world frames). Final state: offline lands at Raito on the spawn hub
with NPCs / players / chat / minimap rendered from recorded VM data.

`recorder/host_recording_stream.py` is the Windows-deployed version
that produced this recording on Apr 29 — pulled directly from
`C:\Users\RC\recorder\`, not from any drifted Mac copy.

External dependencies (referenced, not vendored):

- `~/proj/server-emulator-python3/` — docker-based stub server, used in
  `pair_matcher` mode. `replay.sh` calls it by absolute path; will move
  to a config when v2 lands.
- `~/proj/new-solstice-client/` — Wine client distribution.

## Known issues

- **NPC modals don't open via the form-driver alone.** The injected
  DLL drives Delphi forms but can't fire 3D-scene clicks (NPC clicks
  go through DXRender's depth buffer, not Delphi). Fix: capture raw
  user input (mouse + keyboard) at the host above the VM, replay via
  `CGEvent` against the Wine client.
- **`hvmm.sys` BSOD risk** when the v2 memory-delta thread polls live
  guest RAM. Live introspection on the Lenovo T470 host crashes the
  kernel under sustained read load (bugcheck `0x0a` IRQL_NOT_LESS_OR_EQUAL,
  param1 = `0x1c18` — null deref inside the LeechCore Hyper-V driver).
  v2 carries a `--bsod-safe` toggle that skips everything that loads
  `hvmm.sys`; default is OFF (live mem on by default; toggle on if BSOD
  recurs).

## v2 direction

`recorder/` evolves toward v2:

- Drop form-poller. Input replay supersedes form-driving for replay;
  memory deltas supersede form events for RE annotation.
- Add `input-recorder` thread: `WH_MOUSE_LL` + `WH_KEYBOARD_LL` global
  hooks on the host, foreground-filtered to VMConnect, emit
  `kind:"input_*"` events into the unified JSONL. Always on; not
  gated by `--bsod-safe`.
- Add memory-baseline + per-tick page-delta pipeline (`baseline.zst` +
  `mem.delta.zst`). Gated by `--bsod-safe`: when the flag is set the
  whole memory pipeline is skipped (strict; no `Save-VM` fallback in v2).
- Unify the clock: every JSONL event carries `seq` allocated under the
  `JsonlWriter` mutex at the moment of capture, plus `t_mono_ns` (QPC)
  and `t_wall_ns`. Total ordering across threads is guaranteed by the
  `seq` allocation.

`replay/` follows once the v2 JSONL schema stabilises: replace the
form-driver's "drive form events" step with "synthesize input from
recorded `kind:"input_*"` events at calibrated VMConnect → Wine-window
coordinates."

## Threat model (recording side)

- Recording is **passive**: no transmission, no guest interaction.
  The live server cannot detect the recorder; the in-guest game client
  cannot detect the recorder.
- DLL injection **only happens at replay time**, against the offline
  Wine client. Never against the live VM.
- The server-detection / ban-risk surface lives entirely in *replay-
  against-real-server* scenarios, which this repo does not perform.
  Replay here goes against the in-tree stub server only.
