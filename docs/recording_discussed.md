# Host-Side Recorder — Expansion Plan

**Goal:** extend `host-record.ps1` / `host_recording_stream.py` so that one
PowerShell command produces a forensically complete session bundle for two
purposes:

1. **Replay** the session offline against the running game client (via stub
   server already built separately).
2. **Reverse-engineer** later: figure out which bytes correspond to game state
   (HP, target id, skill cooldowns, NPC modal contents, monster state, etc.).

**Hard constraint — stealth:** all VM/process introspection happens through
`M:\` (MemProcFS, read-only) and host-side `tshark` on the vEthernet adapter.
No guest hooks, no DLL injection, no kernel driver, no writes to guest memory.
The game client and the fan-revived server cannot detect any of this.
Read-only is enforced by saved memory rule
(`Guest VM memory access must be read-only; never write to guest memory`).

---

## 1. What we have today

- `host-record.ps1` orchestrates the session.
- tshark #1 captures **raw all-VM TCP** → `recording_<id>.pcap`.
- `host_recording_stream.py` runs two threads:
  - **form-poller** — watches a curated list of Delphi UI form classes from
    `forms_catalog.json`, reads only the field offsets registered in
    `onclick_catalog.json::form_watcher_fields`, emits change events.
  - **net-sniffer** — spawns tshark #2 filtered to game ports
    (1818/1819/18123/18124), reassembles V2 frames, V2-decrypts world traffic,
    emits per-frame events.
- All events flow through a single mutex-protected `JsonlWriter` →
  `recording_<id>.jsonl`.

---

## 2. What we are adding

A third thread, plus several smaller capture sources, all on one timeline,
all read-only.

### 2.1 Memory-delta thread (the safety net)

Rationale: if the server shuts down or we miss something in the curated form
list, raw memory deltas let us recover.

- **Baseline at session start**: zstd-compressed full snapshot of DXRender
  heap regions (filter same as existing `scan_vmt_instances`: skip `STACK`,
  `TEB`, `*.dll`, `*.exe`, addresses ≥ `0x80000000`).
  → `recording_<id>.baseline.zst` (~30 MB typical).
- **Page-delta loop**: 4 KB pages, xxhash64 hashes kept in RAM. Each tick,
  re-hash and write only changed pages.
  → `recording_<id>.mem.delta.zst`.
- **Adaptive scanning** to keep guest invisible:
  - *Hot* tier (changed within last N ticks) — scanned every tick.
  - *Cold* tier (stable ≥10 ticks) — scanned every 10th tick.
  - After warm-up, typical scan ~50 MB/tick instead of ~400 MB/tick.
- **Region add/remove events** when vmemd file set changes (zone load,
  alloc/free).
- **Read on dedicated thread, process on worker thread** (bounded queue).
  Reader stamps `seq` + `t_mono_ns` at the moment of capture; hashing /
  diffing / zstd / disk write all happen async. Queue full → emit
  `{"kind":"mem_skip"}` rather than back-pressure the reader.

### 2.2 All-forms full-instance recorder

The existing form-poller only watches **manually-curated offsets** for forms
that have entries in `form_watcher_fields`. Extension:

- Iterate **every** entry in `forms_catalog.json`.
- On `form_appear`, dump the full `instance_size` bytes.
- On each tick, read full instance bytes, delta-compress per-instance.
- Emit `kind:"form_full"` events with delta payloads.

This catches every UI screen / modal / widget without needing pre-known
offsets, which is exactly what you want for RE.

### 2.3 Module / thread / version snapshot

At session start and whenever the loaded-module list changes:

- Loaded DLLs from `M:\pid\<pid>\modules` — base, size, path, PE timestamp,
  SHA-256.
- Threads from `M:\pid\<pid>\threads`.
- Main exe build identity (PE timestamp, version resource, SHA-256).

→ `recording_<id>.modules.json` plus inline `kind:"module_change"` events.

Without this you cannot translate a code address back to "dxrender.exe +
0x12340" months later.

### 2.4 Window / viewport metadata

Recorded at session start and on resize:

- DXRender window client-area rect.
- DPI, fullscreen vs windowed.
- Monitor topology.

Inline as `kind:"viewport"` events.

### 2.5 Server endpoint extraction

Parse pcap stream once at startup to identify which IPs/ports the client
actually contacts. Emit `kind:"server_endpoint"` events. Makes stub-server
configuration trivial later.

### 2.6 Entity recorder *(future, blocked on RE work)*

Same machinery as the form recorder but pointed at engine-side classes
(monsters, NPCs, players, projectiles, ground items) — `TActor`/`TCreature`/
`T3DObject` or whatever the catalog turns out to be. Builds an entity catalog
parallel to the form catalog. Not in scope for this round.

### 2.7 Explicitly **not** doing

- **Filesystem capture.** Punted. MemProcFS gives only partial file
  reconstruction from page cache; doing it properly means VSS-snapshotting
  the VHDX, which overlaps almost completely with what memory deltas already
  capture. If a specific file ever turns out to matter, we can add an
  opportunistic `Checkpoint-VM` at session-end as a one-liner.
- **Audio capture.** Game client loads audio per-map; replay reproduces it.
- **Screen capture.** Optional human-verification aid only; skipped by default.
- **Input capture.** Deferred until network-only replay reveals what actually
  needs input synthesis. Resolution differences make pixel-level replay
  fragile; if/when added, prefer **form/widget-level recording** (record
  *which form's button #N was clicked*, not *pixel (847, 423)*) so replay is
  resolution-independent.
- **Memory write-back / replay-by-injection.** Detectable, breaks stealth
  rule. Replay is server-side (stub) + optional input synthesis only.

---

## 3. Time, ordering, and synchronisation

### 3.1 Single source of time

Every JSONL event carries:

- `t_mono_ns` — `time.monotonic_ns()` for ordering and pcap correlation.
- `t_wall_ns` — `time.time_ns()` for human-readable timestamps.
- `seq` — global monotonic sequence number, allocated under the
  `JsonlWriter` mutex **at the moment of capture**, not at the moment of
  write.

### 3.2 Ordering guarantee

Replay sorts JSONL by `seq`. Because `seq` is allocated at capture time
under a mutex, ordering is correct regardless of how late the writer thread
flushes the line. Worker-thread compression / disk writes can lag arbitrarily;
order is preserved.

### 3.3 Pcap ↔ JSONL alignment

On Windows, both Npcap (tshark capture source) and Python's `time.time_ns()`
ultimately read the same hardware clock (QPC via
`GetSystemTimePreciseAsFileTime`). They are aligned to within a few
microseconds without any beacon. **No sync packet needed.**

### 3.4 Important nuance: late *processing* yes, late *reading* no

`M:\` is a live view of guest RAM, not a time machine. If we read at t+5,
we get t+5's bytes, not t's. So:

| Stage | Deferable? |
|---|---|
| Read (`open(vvmem).read()`) | **No** — must happen at snapshot time |
| Hash / diff / compress / write to disk / emit JSONL | **Yes** |

The mem-recorder reads on its cadence, then everything else is pipelined
through a worker thread.

---

## 4. Performance & stealth budget

Cost lives almost entirely in MemProcFS reads. Everything else (host CPU,
host disk) is invisible to the guest.

| Source | Cadence | Bytes read/sec | Guest impact |
|---|---|---|---|
| Form-poller (existing) | 10 Hz | ~MB/s | none observed |
| Per-form full-instance dump | 1–2 Hz | ~1 MB/s | negligible |
| Page-delta heap scan (warm) | 1 Hz | ~50 MB/s | minimal |
| Page-delta heap scan (cold start) | 1 Hz, briefly | ~400 MB | brief |
| Module / thread snapshot | every 30 s | trivial | none |
| Baseline (one-shot) | t=0 | ~300 MB once | brief, tolerable |

Tuning levers in the new `host-record.ps1`:

- `-MemHz 1` (default), `-MemHz 0.5` for safer, `-MemHz 2` for finer.
- `-NoMem` kill-switch.
- zstd level 3 (single-thread, ~3 GB/s) — within ~10 % of zstd-19 ratio on
  random binary data, dramatically less CPU.
- Bound queue depth = 8 ticks. Queue full → log skip, do not back-pressure.

Realistic total at 1 Hz with adaptive scanning, post warm-up: **host CPU
~5–15 % of one core; guest impact unmeasurable**. The same hypervisor
introspection mechanism is used by EDR/AV products; a game client cannot
detect it without an external trusted clock, which it does not have.

---

## 5. Output bundle (per session)

```
recording_<id>.pcap                  raw all-VM TCP (safety net, untouched)
recording_<id>.jsonl                 unified timeline: net | form | mem | module
recording_<id>.baseline.zst          full memory snapshot @ t=0
recording_<id>.mem.delta.zst         4 KB-page deltas, hot/cold tiered
recording_<id>.forms.delta.zst       per-form-instance full-byte deltas
recording_<id>.modules.json          DLL / thread / version snapshots
recording_<id>.entities.delta.zst    (future, after entity catalog)
```

---

## 6. Build order

1. **Clock unification + global `seq` + dual-timestamp on every event.**
   Foundation everything else relies on.
2. **Memory baseline + adaptive page-delta thread** with worker pipeline.
3. **All-forms full-instance recorder** (extends existing form-poller).
4. **Module / thread / version snapshot** at start + on change.
5. **Window/viewport metadata + server-endpoint extraction.**
6. **(Optional, behind flag)** screen capture for human verification.
7. **Entity recorder** — blocked on entity-catalog RE.
8. **Input recorder** — only after network-only replay shows what needs it,
   and prefer form/widget-level recording over pixel-level.

---

## 7. Architecture diagram

```
                                  ┌─────────────────────────────────────────────┐
                                  │           GUEST VM (game client)            │
                                  │   ┌─────────────────────────────────────┐   │
                                  │   │  DXRender.exe — Delphi/D3D process  │   │
                                  │   │   heap | forms | entities | sockets │   │
                                  │   └─────────────────────────────────────┘   │
                                  │           ▲                  │              │
                                  │   live RAM│      TCP frames  │              │
                                  └───────────┼──────────────────┼──────────────┘
                                              │ (read-only,      │
                                              │  invisible to    │
                                              │  guest)          │
                ┌─────────────────────────────┴──────┐    ┌──────▼──────────┐
                │   MemProcFS  →  M:\pid\<pid>\...   │    │  vEthernet NIC  │
                │   memory.vmem | vmemd\*.vvmem      │    │   (host side)   │
                │   modules | threads | name.txt     │    └──────┬──────────┘
                └─────────────────────────────────────┘           │
                                                                  │ passive sniff
                  ┌──────────────────────────────────────────────┬┴──────────────┐
                  │                  HOST  (host-record.ps1)     │               │
                  │                                              ▼               │
                  │                                       ┌─────────────┐        │
                  │                                       │  tshark #1  │        │
                  │                                       │  raw all-VM │ ─────► recording_<id>.pcap
                  │                                       │  TCP capture│        │
                  │                                       └─────────────┘        │
                  │                                                              │
                  │                                       ┌─────────────┐        │
                  │                                       │  tshark #2  │        │
                  │                                       │ game ports  │        │
                  │                                       │ (1818/19/   │        │
                  │                                       │  18123/24)  │        │
                  │                                       └──────┬──────┘        │
                  │                                              │ pcap on stdout │
                  │                                              ▼                │
                  │  ┌────────────────────────────────────────────────────────┐  │
                  │  │      host_recording_stream.py — single process         │  │
                  │  │                                                        │  │
                  │  │  ┌─────────────┐  ┌────────────┐  ┌─────────────────┐  │  │
                  │  │  │ form-poller │  │net-sniffer │  │  mem-recorder   │  │  │
                  │  │  │  (10 Hz)    │  │            │  │   (1 Hz read)   │  │  │
                  │  │  ├─────────────┤  ├────────────┤  ├─────────────────┤  │  │
                  │  │  │ scan VMTs   │  │ parse pcap │  │ vmemd→pages     │  │  │
                  │  │  │ form_appear │  │ V2 frames  │  │ adaptive tier   │  │  │
                  │  │  │ form_destroy│  │ V2 decrypt │  │ stamp seq + t   │  │  │
                  │  │  │ field deltas│  │ (world)    │  │ push to queue ──┼─┐│  │
                  │  │  │ instance    │  │ opcode +   │  │                 │ ││  │
                  │  │  │ full-byte   │  │ payload    │  │                 │ ││  │
                  │  │  │ delta       │  │            │  │                 │ ││  │
                  │  │  └──────┬──────┘  └─────┬──────┘  └─────────────────┘ ││  │
                  │  │         │               │                             ││  │
                  │  │         │               │         ┌──────────────────┐││  │
                  │  │         │               │         │ mem-worker thread│◄┘│  │
                  │  │         │               │         │ ─────────────────│  │  │
                  │  │         │               │         │ xxhash64 pages   │  │  │
                  │  │         │               │         │ diff vs last     │  │  │
                  │  │         │               │         │ zstd-3 changed   │  │  │
                  │  │         │               │         │ append to file ──┼──┼─► recording_<id>.mem.delta.zst
                  │  │         │               │         │ emit JSONL evt   │  │  │
                  │  │         │               │         └────────┬─────────┘  │  │
                  │  │         │               │                  │            │  │
                  │  │         │               │         ┌────────▼─────────┐  │  │
                  │  │         │               │         │ module/thread    │  │  │
                  │  │         │               │         │ snapshot         │  │  │
                  │  │         │               │         │ (30s + on chg)   │  │  │
                  │  │         │               │         └────────┬─────────┘  │  │
                  │  │         │               │                  │            │  │
                  │  │         ▼               ▼                  ▼            │  │
                  │  │  ┌──────────────────────────────────────────────────┐   │  │
                  │  │  │            JsonlWriter  (mutex)                  │   │  │
                  │  │  │   next_seq() — monotonic, allocated AT capture   │   │  │
                  │  │  │   each event:  {seq, t_mono_ns, t_wall_ns, ...}  │   │  │
                  │  │  └──────────────────────────┬───────────────────────┘   │  │
                  │  └─────────────────────────────┼───────────────────────────┘  │
                  │                                │                              │
                  │                                ▼                              │
                  │                       recording_<id>.jsonl                    │
                  │                       recording_<id>.baseline.zst             │
                  │                       recording_<id>.modules.json             │
                  │                                                               │
                  └───────────────────────────────────────────────────────────────┘

                                        ──────  output bundle  ──────

      recording_<id>.pcap            ◄ raw all-VM TCP (safety net)
      recording_<id>.jsonl           ◄ unified timeline: net | form | mem | module events
      recording_<id>.baseline.zst    ◄ full memory snapshot @ t=0
      recording_<id>.mem.delta.zst   ◄ 4 KB-page deltas, hot/cold tiered
      recording_<id>.modules.json    ◄ DLL/thread/version snapshots


      KEY ORDERING RULE
      ─────────────────
      seq is allocated at the MOMENT OF CAPTURE under a single mutex.
      Writes/compression can lag arbitrarily — replay sorts by seq and
      is guaranteed correctly ordered. pcap timestamps come from the
      same hardware clock (QPC) as t_mono_ns and align post-hoc.


      STEALTH BOUNDARY
      ────────────────
      Everything above the dashed line at the top runs inside the guest
      and is the game client. Everything below runs on the host and is
      invisible to the guest:
        • MemProcFS reads      → hypervisor-level, no guest hooks
        • tshark               → host NIC sniff, passive
        • No writes to guest   → enforced; never crossed
```

---

## 8. Runtime flow chart

```
                              ┌────────────────────────────┐
                              │  user runs host-record.ps1 │
                              │     <session_id>           │
                              └─────────────┬──────────────┘
                                            │
                                            ▼
                              ┌────────────────────────────┐
                              │ check M:\ mounted?         │
                              │ check tshark exists?       │
                              │ check session id unused?   │
                              └─────────────┬──────────────┘
                                            │ ok
                                            ▼
                              ┌────────────────────────────┐
                              │ start tshark #1            │
                              │ (raw all-VM TCP → pcap)    │
                              └─────────────┬──────────────┘
                                            │
                                            ▼
                          ┌─────────────────────────────────┐
                          │ poll M:\pid for DXRender name   │◄──┐
                          │ found?                          │   │ wait 200ms
                          └────────────┬────────────────────┘   │ (max 600s)
                                       │ no  ─────────────────────┘
                                       │ yes
                                       ▼
                              ┌────────────────────────────┐
                              │  launch python recorder    │
                              │  --pid <dxr> --id <s>      │
                              └─────────────┬──────────────┘
                                            │
                                            ▼
                              ┌────────────────────────────┐
                              │  build form/entity tables  │
                              │  open JsonlWriter          │
                              │  emit session_start        │
                              └─────────────┬──────────────┘
                                            │
                       ┌────────────────────┼────────────────────────────┐
                       │                    │                            │
                       ▼                    ▼                            ▼
              ┌───────────────┐    ┌───────────────┐          ┌────────────────────┐
              │ form-poller   │    │ net-sniffer   │          │  mem-recorder      │
              │ thread        │    │ thread        │          │  thread (read)     │
              └───────┬───────┘    └───────┬───────┘          └─────────┬──────────┘
                      │                    │                            │
                      ▼                    ▼                            ▼
              ┌───────────────┐    ┌───────────────┐          ┌────────────────────┐
              │ resolve VMTs  │    │ spawn tshark  │          │ enumerate vmemd    │
              │ scan heap     │    │ #2 → stdout   │          │ filter heap only   │
              │ list live     │    │ pcap stream   │          │ skip stack/dll/exe │
              └───────┬───────┘    └───────┬───────┘          └─────────┬──────────┘
                      │                    │                            │
                      ▼                    ▼                            ▼
              ┌───────────────┐    ┌───────────────┐          ┌────────────────────┐
              │ on tick:      │    │ on packet:    │          │  baseline (once):  │
              │  read fields  │    │  parse eth/   │          │   read all pages   │
              │  read full    │    │   ip/tcp      │          │   xxhash each 4KB  │
              │  instance     │    │  reassemble   │          │   zstd → file      │
              │  diff vs prev │    │  V2 frames    │          │   record hashes    │
              └───────┬───────┘    └───────┬───────┘          └─────────┬──────────┘
                      │                    │                            │
                      ▼                    ▼                            ▼
              ┌───────────────┐    ┌───────────────┐          ┌────────────────────┐
              │ change?       │    │ world port?   │          │ on tick:           │
              ├───────┬───────┤    ├──┬─────────┬──┤          │  pick pages by tier│
              │ yes   │ no    │    │yes│       │no│          │   hot=every tick   │
              │       │ skip  │    │   │       │  │          │   cold=every 10th  │
              ▼       └───────┘    ▼   │       ▼  │          │  read those pages  │
              │                    │   │       │  │          └─────────┬──────────┘
              │           ┌────────┘   │       │  │                    │
              │           │            │       │  │                    ▼
              │           ▼            │       │  │          ┌────────────────────┐
              │   ┌───────────────┐    │       │  │          │ allocate seq+t     │
              │   │ V2 decrypt    │    │       │  │          │ push (seq,t,pages) │
              │   │ extract opcode│    │       │  │          │ to bounded queue   │
              │   │ + payload     │    │       │  │          └─────────┬──────────┘
              │   └───────┬───────┘    │       │  │                    │
              │           │            │       │  │                    ▼
              │           │   ┌────────┘       │  │          ┌────────────────────┐
              │           │   │                │  │          │ queue full?        │
              │           │   │                │  │          ├──────┬─────────────┤
              │           │   │                │  │          │ no   │ yes         │
              │           │   │                │  │          │      ▼             │
              │           │   │                │  │          │  emit mem_skip     │
              │           │   │                │  │          │  drop tick         │
              │           │   │                │  │          │      │             │
              │           │   │                │  │          │      ▼             │
              │           │   │                │  │          │  ┌────────────────────┐
              │           │   │                │  │          │  │  mem-worker thread │
              │           │   │                │  │          │  │  (drain queue)     │
              │           │   │                │  │          │  └─────────┬──────────┘
              │           │   │                │  │          │            │
              │           │   │                │  │          │            ▼
              │           │   │                │  │          │  ┌────────────────────┐
              │           │   │                │  │          │  │ hash each page     │
              │           │   │                │  │          │  │ diff vs last hash  │
              │           │   │                │  │          │  │ promote/demote tier│
              │           │   │                │  │          │  └─────────┬──────────┘
              │           │   │                │  │          │            │
              │           │   │                │  │          │            ▼
              │           │   │                │  │          │  ┌────────────────────┐
              │           │   │                │  │          │  │ any changed?       │
              │           │   │                │  │          │  ├──────┬─────────────┤
              │           │   │                │  │          │  │ no   │ yes         │
              │           │   │                │  │          │  │      ▼             │
              │           │   │                │  │          │  │  zstd-3 + append   │
              │           │   │                │  │          │  │  to .delta.zst     │
              │           │   │                │  │          │  │      │             │
              ▼           ▼   ▼                ▼  ▼          ▼  ▼      ▼             │
              ┌─────────────────────────────────────────────────────────────────────┐
              │                  JsonlWriter.emit({...})                            │
              │   ─────────────────────────────────────────────────                 │
              │   acquire mutex                                                     │
              │   if no seq supplied: seq = next_seq()  (else use captured seq)     │
              │   t_mono_ns = monotonic_ns()  (or use captured t)                   │
              │   t_wall_ns = time_ns()       (or use captured t)                   │
              │   write json line                                                   │
              │   release mutex                                                     │
              └─────────────────────────────┬───────────────────────────────────────┘
                                            │
                                            ▼
                              ┌────────────────────────────┐
                              │  Ctrl+C  /  signal         │
                              └─────────────┬──────────────┘
                                            │
                                            ▼
                              ┌────────────────────────────┐
                              │ stop_evt.set()             │
                              │ join all threads (5s ea)   │
                              │ drain mem-worker queue     │
                              │ flush JsonlWriter          │
                              │ stop tshark #1             │
                              │ emit session_stop          │
                              └─────────────┬──────────────┘
                                            │
                                            ▼
                              ┌────────────────────────────┐
                              │  output bundle written:    │
                              │   .pcap                    │
                              │   .jsonl                   │
                              │   .baseline.zst            │
                              │   .mem.delta.zst           │
                              │   .modules.json            │
                              └────────────────────────────┘
```

---

## 9. FAQ

### Q1. When I run `host-record.ps1 phase3_walk_v7`, does it record everything in memory? Or just certain UI menu events? I want to record gameplay such as an archer using a ranged skill on a monster.

**Today's recorder captures three streams, none of which is "all of memory."**

1. **Form-poller** (`kind:"form"`) — only watches Delphi UI form instances
   listed in `forms_catalog.json`, and only the field offsets registered in
   `onclick_catalog.json::form_watcher_fields`. This is the "UI menu events"
   channel: login screen, char select, inventory open, etc. It will **not**
   see an archer firing a skill unless that action mutates a watched offset
   on a watched form.
2. **Net-sniffer** (`kind:"net"`) — tshark filtered to ports
   1818/1819/18123/18124, V2 frames reassembled, world port 18123 V2-decrypted.
   **This is where ranged-skill / monster combat lives** — those are
   world-server packets (skill request C2S, damage / HP S2C). Emitted as
   JSONL with opcode + decrypted payload hex.
3. **Raw pcap** — separate tshark capturing **all** VM TCP into
   `recording_<id>.pcap`, untouched by the JSONL parser. Full replay
   material if ever needed.

So combat is captured (as decoded packets and raw pcap), but state like
HP / target id / cooldowns isn't extracted unless those offsets are added
to `form_watcher_fields` — or until we add the memory recorder.

### Q2. Is there something similar to Raw pcap, where all network gets collected? I want all memory to be collected.

There is no streaming "raw pcap of memory" — process memory is hundreds of
MB to a few GB and changes constantly, so naïve continuous full dumps would
write GB/s and be unreadable. Realistic options, ordered by effort:

1. Periodic full snapshots via MemProcFS (huge, viable only for short
   sessions and N ≥ 30 s).
2. Hyper-V checkpoints (heavy, replayable, good for "rewind a 5-minute
   combat" not for continuous recording).
3. **Watched-region dumps** — dump full instance bytes for known structures,
   delta-compress.
4. **Targeted struct logging** — find the offsets and watch them.

The build plan picks (3) plus a generic (1)-style baseline + page deltas as
a safety net.

### Q3. I don't actually know where they are in memory, that's why I want raw — it'll be easier to decipher later.

Right approach. Snapshot now, find offsets later by diffing snapshots
against timestamped events. The **page-delta** scheme captures all heap
state with reasonable overhead and is exactly what you want for that workflow.

### Q4. Could we do a baseline then only record changes? Or does it all change?

Baseline + delta works very well. Most of a game process's heap is stable:
loaded textures / meshes, item DB, skill tables, string pools. Typically
60–80 % of total heap and basically never changes after load. The churn is
concentrated in a smaller working set:

- *Static*: zero deltas, free.
- *Slow-churn* (HP, position, inventory, target id, cooldowns): a few
  pages/sec — the data you actually want.
- *Noise* (allocator metadata, render command rings, audio mixer, network
  rx buffers, animation interpolators): constant churn. Compresses well,
  filterable post-hoc.

Rough budget at 1 Hz delta: baseline ~30 MB, then ~0.5–5 MB/sec compressed.
**10-minute session ≈ 300 MB–3 GB**, vs 10–30 GB for naïve full snapshots.

### Q5. I want it built into the same `host-record.ps1`. Replay must use the actual game client (not a video). Stealth must be preserved — all reads through `M:\`, no writes to guest, real fan-revived server unaware.

Confirmed. Everything goes through `M:\` (read-only by construction) and
host-side tshark. No guest-side hooks/injection/driver/writes, ever.

**Important architectural clarification:** "replay through the game client"
is a *network-replay* problem, not a memory-replay problem. Memory replay
would require writing to guest RAM, which breaks the stealth rule. You
already have the raw pcap and decoded JSONL — those are what feed the stub
server during replay. Memory recording earns its keep as a **decoding aid
for offline RE**, not as a replay mechanism.

### Q6. I have network replay already, but it doesn't open NPC modals or fight monsters — that has to be initiated by the client. Is that the right approach?

Half-right. You're correct that NPC modals / hitting monsters are
client-initiated — the client sends C2S "I clicked NPC #47" / "use skill
on entity 9281", and the server responds. Stub-server replay alone can't
start the conversation. But:

- For most server-authoritative MMOs, animations / state effects fire from
  S2C, so once the C2S kicks off, the client renders the rest from S2C.
- The cleanest way to recreate the C2S is **not pixel input replay** (fragile)
  but either (a) form/widget-level click recording — record *which form's
  button N was clicked*, replay by resolving the form and synthesising a
  click at its current screen rect (resolution / DPI / layout independent);
  or (b) inject the recorded C2S packet directly.
- Run network-only replay against the live client first to find out what
  actually doesn't fire. *Then* decide which gaps need input synthesis.

### Q7. User input has been hard to replay (resolution diffs etc.).

Resolution is solvable (normalize to client-area %). The harder problems
are world-state divergence (camera, char pos, mob position) and timing/RNG.
Pixel-perfect replay is fragile; record at the form/widget level when
possible (resolution-independent) and treat true world-space clicks as a
last resort.

### Q8. Are we able to just record every form? Why is it filtering? Do monster objects count as forms?

The filtering is **manual curation, not a technical limit.**
`form_watcher_fields` only lists forms with hand-picked offsets. Recording
every form is fine and is now in the plan (§ 2.2): iterate every entry in
`forms_catalog.json`, dump full instance bytes, delta-compress.

**Monsters are not forms.** In Delphi/DXRender games:

- Forms / `TDnc*` widgets = UI: windows, panels, buttons, modals, hotkey
  bars, chat box.
- Monsters / NPCs / players / projectiles / ground items = engine-side
  scene actors, different class hierarchy (e.g. `TActor`, `TCreature`,
  `T3DObject`), owned by a world / scene manager singleton, not a form.

Same VMT-scan technique works to capture them, but they need a parallel
**entity catalog**. That's its own RE step — see § 2.6.

### Q9. We need timestamps right or we get out-of-order. What else are we missing for replay and RE?

Time/ordering — see § 3. Single hardware clock (QPC) is shared by Npcap and
Python's `time_ns()`, so pcap and JSONL align without a beacon. Add a global
`seq` allocated at capture time for total ordering across threads.

Other things added to the plan to avoid regret later:

- **Module / thread / version snapshots** — needed to translate a code
  address back to "dxrender.exe + 0x12340" months later.
- **Window / viewport metadata** — needed for any visual reconstruction.
- **Server endpoint extraction** — makes stub-server config trivial.
- **Full memory baseline at t=0** — table of contents for RE.

Things explicitly **not** added: filesystem capture, audio, screen capture
(by default), input recording (deferred), memory write-back replay
(forbidden by stealth rule).

### Q10. Is this going to be heavy? I don't want it detectable (slowing the VM might hint).

Expected impact at 1 Hz with adaptive scanning post warm-up: **host CPU
~5–15 % of one core; guest impact unmeasurable.** Detail in § 4.

Levers: `-MemHz` (default 1, configurable), `-NoMem` kill switch, zstd-3
single-thread, bounded queue with skip-on-full rather than back-pressure,
adaptive hot/cold tier scanning.

Hyper-V live introspection is the same mechanism EDR/AV products use; a
game client can't time-detect it without an external trusted clock, which
it doesn't have.

### Q11. Do we need filesystem I/O? Maybe baseline + diffs?

Punted. Reasons in § 2.7. MemProcFS only partially reconstructs files
from page cache; doing it properly means VSS-snapshotting the VHDX, which
overlaps almost completely with what memory deltas already capture.
Replay drives the live client which recreates its own logs/caches.
If a specific file ever turns out to matter, an opportunistic
`Checkpoint-VM` at session-end is a one-line PowerShell add.

### Q12. Since `M:\` is read-only, can we record memory late and queue it correctly?

**Late processing yes; late reading no.** `M:\` is a live view of guest
RAM, not a time machine — reading at t+5 returns t+5's bytes, not t's.

So:

- The read itself must happen at snapshot time.
- Hashing, diffing, compression, disk write, JSONL emit can all be deferred
  to a worker thread.
- A global `seq` allocated under the `JsonlWriter` mutex at the moment of
  capture guarantees ordering regardless of how late the worker flushes.

See § 3.4 for the table.

---

## 10. Open question before build

- **zstd dependency.** Plan uses `zstandard` (PyPI). Confirm that's OK to
  pip-install, or fall back to stdlib `gzip` (3–4× worse compression but
  zero new deps).

Reply **"go"** when ready — or **"go, gzip"** to skip the zstd install.
