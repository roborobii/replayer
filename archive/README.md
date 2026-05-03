# archive/

Frozen reference material from before v2. Nothing here is on the active
build path. Top-level `recorder/` and `replay/` will appear when v2
lands and hold the new code; this `archive/` stays as the historical
checkpoint.

## Directories

### `recorder/` — v1 recorder (the working pipeline)

The 5 files that produced `captures/phase3_walk_v4.jsonl` end-to-end.
Pulled byte-identical (SHA-256 verified) from `C:\Users\RC\recorder\`
on the recording host before that directory was deleted.

```
host-record.ps1            ← entry point. Launcher: starts tshark,
                              waits for DXRender PID, runs the python
                              recorder, cleans up on Ctrl+C.
host_recording_stream.py   ← actual recorder. Two threads: form-poller
                              + V2-decoded net-sniffer. Imports
                              v2cipher.py; reads forms_catalog.json
                              and onclick_catalog.json by default.
v2cipher.py                ← V2 stream cipher decrypt. Stdlib only.
forms_catalog.json         ← Delphi VMT catalog for the form-poller.
onclick_catalog.json       ← form watch fields + click handlers.
```

v2 drops the form-poller, so `forms_catalog.json` /
`onclick_catalog.json` aren't needed by v2. v2 will still use a
descendant of `v2cipher.py` (with encrypt direction added) for the
new replayer.

### `replay/` — v1 replay flow (DLL injection + docker stub)

```
recording_replayer.py      ← Python; injects a DLL into Wine's
                              XenClient and drives Delphi forms by
                              VMT class name; gates net to coordinate
                              with the docker pair-matcher stub.
replay.sh                  ← one-shot orchestrator: tear down Wine,
                              boot stub server in PAIR_MATCH mode,
                              launch Wine client, run the replayer,
                              screenshot.
```

Superseded by v2's design (real Windows on RC3 + PostMessage helper +
Mac-side replayer). Kept here as historical reference for the
pair-matching idea.

### `captures/` — recorded sessions

29 game-port-filtered pcaps + `phase3_walk_v4.jsonl`. The JSONL is
the only one of these that's been confirmed to replay end-to-end and
is the **test fixture for v2 Phase A** (replayer-against-existing-v1-JSONL).

Pcaps were filtered (display filter on game ports 1818/1819/18123/18124)
from much larger raw captures on the recording host before delete; the
1.9 GB of raw web/CDN noise was discarded.

### `vm/` — Hyper-V VM management scripts (active use)

```
restart-elf.ps1            ← stops MemProcFS, stops VM, pins
                              resolution to 1440x900, disables
                              enhanced session, starts VM, opens
                              VMConnect, mounts MemProcFS at M:\
                              once heartbeat is OK.
shutdown-elf.ps1           ← stops MemProcFS, stops VM, closes
                              VMConnect.
```

These run on the recording host. Used as-is in normal operation; v2
recording will continue to depend on `restart-elf.ps1` to bring up
the VM at the right resolution.

### `input-agent/` — host-side input recorder (lifted for v2)

The pre-existing implementation of host-side `WH_MOUSE_LL` /
`WH_KEYBOARD_LL` hooks scoped to vmconnect.exe. The v2 recorder
**lifts `host_agent.py`** as the basis for its input thread.

```
start_input_agent.ps1      ← launcher (runs python host_agent.py)
host_agent.py              ← pynput-based LL hook implementation.
                              Filters events to vmconnect foreground;
                              emits JSONL with fractional client-area
                              coords. ~194 lines.
host_input_capture.c       ← alternative C implementation of the
                              same idea; not built or used currently.
mac_replay.py              ← companion Mac-side replayer from the
                              original experiment; informs v2 replay
                              design but doesn't run as-is.
README.md                  ← original experiment notes from
                              ~/proj/failed_experiments/input_mirror/
```

### `docs/` — design discussion and project context

Five text/Markdown files preserving the design rationale:

```
flows-to-record.txt                       ← gameplay flows targeted
                                            for recording (NPC modal,
                                            combat, items, skills...)
plan.txt                                  ← earlier RE plan / context
recording_discussed.md                    ← v2 design discussion (md)
recording_discussion.txt                  ← v2 design discussion (raw
                                            transcript)
reverse-engineering-help-email.txt        ← 2020 email seed of the RE
                                            project
```

The two `recording_discuss*` files are the same content in different
formats; both byte-identical to the host-side originals (SHA-256
verified).

## What got pruned and where to find it

A handful of v1 auxiliary scripts were pruned during reorg as not
on the v2 build path. They're recoverable from git history if needed:

| Pruned | What it was | Recover via |
|---|---|---|
| `recorder/notes/alt-recorder/Record-Session.ps1` + `record_session.py` | Click-driven memory snapshot recorder, alternative design from the polling form-poller. Insights captured in `docs/recording_discussed.md`. | `git log --all -- '*Record-Session*' '*record_session.py'` |
| `recorder/notes/re-helpers/find_vmt_for_classname.ps1`, `find_ptrs.ps1`, `dump_va.ps1`, `mem_search.ps1`, `snap_mem.ps1`, `check_vmc.ps1` | MemProcFS-based RE utilities for offline analysis (search, dump, VMConnect window geometry). Useful when actually doing RE; not on v2 record/replay path. | `git log --all -- 'archive/recorder/notes/re-helpers/*'` |
| `vm/check-elf-res.ps1` | Interactive credential-prompt to check VM display resolution from inside the guest. Niche. | `git log --all -- '*check-elf-res*'` |

## Pointers for tomorrow's agent

- **Phase A test fixture:** `captures/phase3_walk_v4.jsonl` — the replayer must drive this end-to-end as its win condition.
- **Phase B starting point:** `input-agent/host_agent.py` is the working LL hook implementation; lift its hook setup, foreground filter, and JSONL emit pattern into the new recorder thread.
- **Cipher reuse:** `recorder/v2cipher.py` is decrypt-only today. The replayer needs encrypt direction added — either extend in place or fork to `replay/v2cipher.py` in the new top-level `replay/`.
- **Pair-matcher source of truth:** lives outside this repo at
  `~/proj/server-emulator-python3/` (docker container, `pair_matcher` mode).
  Read its matching algorithm before reimplementing.
