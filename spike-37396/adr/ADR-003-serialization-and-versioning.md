# ADR-003 — Flat event layout & contract versioning

**Status:** Proposed (spike #37396), **updated for ADR-001 = option (b).** **Consolidates:** `03-event-contract-spec.md` §2/§4 into a decision record. **Corroborated by:** `02-peer-research.md` (Falco scap, Inspektor Gadget, Hubble).

## Context

Under ADR-001 (b) the eBPF component is a **shared library linked into each module**; events are consumed **in the same process** — there is **no IPC and no serialized wire format**. The event layout is therefore an **in-process ABI** between the shared library and the module that links it. What still must hold: **no new external dependency** (no protobuf, no gRPC, no FlatBuffers — hand-rolled flat C), and the library and its linking modules **ship on independent cadences** (a module built against an older library header; a packaged `.so` upgraded under an older module), so the layout + versioning must let a newer library work with an older module and vice-versa. That independent-shipping requirement survives the (a)→(b) change unchanged; only the transport (socket → linked library) drops out.

## Decision

### D1 — Layout: fixed header + packed payload + length-delimited trailing strings
- A fixed, naturally-aligned `rt_event_header` (`03-event-contract-spec.md §2`) begins every event and carries `total_len`.
- A per-class fixed payload struct follows.
- Variable data (paths, comm, args) are `{uint16_t len; bytes[len]}` runs after the fixed payload, in a declared order.
- **`total_len` is authoritative**: a reader that doesn't recognize a field, a type, or a trailing extension skips to `hdr + total_len`. This mirrors Falco's scap encoding (a `len` that includes the header so unknown events forward/skip cleanly) — a verified pattern. It applies to iterating in-process events just as it did to framed ones.

### D2 — Native structs, in-process ABI guard (no socket handshake)
- Delivery is same-process → **native byte order, natural alignment, no serialization step**. Events are plain C structs the module reads directly.
- The ABI guard is a **compile-/load-time** check, not a connection handshake: at `rt_open` the library reports `abi_major`/`abi_minor`; the linking module refuses on a **major** mismatch. `abi_major` is also echoed in **every** event header so a module self-protects if it links a `.so` whose ABI differs from the header it compiled against. (The earlier `magic`/`endian`/socket-handshake framing is dropped — same-process removes the need.)

### D3 — Type-table-driven decode, one shared header
- A static `rt_event_type → schema` table (fixed-payload size, trailing-string order) lives in **one header shipped by the shared library** and compiled into every linking module. Decoders are table-driven, never guessed. This is Falco's `g_event_info` model (`02-peer-research.md` pattern 2). One header = the table cannot drift between library and module.

### D4 — Versioning policy (semver, append-only growth)
| Change | Version bump | Compatibility |
|---|---|---|
| Append field to header/payload tail; add new `rt_event_type` | **MINOR** | Backward+forward compatible. Older module ignores the tail / never installs the new type. Newer module linked against an older library sees a short `payload_len` → treats the appended field as absent. |
| Remove/reorder/resize/renumber/repurpose a field or type | **MAJOR** | Incompatible. Module refuses at `rt_open` on `abi_major` mismatch; per-event `abi_major` self-guards. |

Shared policy across Falco/Tetragon/Inspektor Gadget (verified) — minor = add, major = break. Applied here to a **library ABI** rather than a wire protocol.

### D5 — Correlation keys are schema fields, not a side channel
Raw join keys (`cgroup_id`, `mnt_ns`, `pid_ns`, `net_ns`, `pid/tid`) are **typed fields in the header**, defined-absent = `0`. Container enrichment is a separate consumer-side step joining on them (Inspektor Gadget's `gadget_mntns_id` model). The library never carries a container id. Empty keys are valid (host use) — see `03-event-contract-spec.md §6`. Aligned with #37382's recorded key decision (`03 §7b`).

### D6 — Drops are in-band and typed, never silent
`dropped` counter + `RT_F_DROPS_BEFORE` flag in the header expose the module's own loss; kernel-ringbuf-full is a separate typed counter (per module). All four peer projects treat silent drops as a correctness/security bug (`02-peer-research.md` pattern 7). A dropped event = a missed FIM/Syscollector state, so loss must be observable — this holds identically under (b), per module.

## Rejected alternatives
- **protobuf/gRPC** (Tetragon/Hubble bus) — new external dependency; violates hard constraint. (Also moot under (b): no transport at all.)
- **Self-describing / TLV-everywhere records** — parse cost + size overhead; the fixed-header+table approach is cheaper and equally evolvable via append-only growth.
- **Dynamic plugin ABI with runtime symbol resolution** (Falco plugin model) — overkill for two in-tree modules; a normal shared library + compiled schema header is simpler and has no runtime symbol-resolution risk. (Note (b) *does* make the eBPF component a shared library, but linked normally at build time, not a discovered plugin.)

## Consequences
- One in-process layout, no transport, no serialization library.
- The shared library and the modules linking it evolve independently under the minor/major rule (D4) — the reason versioning is kept even though there is no wire.
- The shared type-table/ABI header is a coordination point: **any payload change is a cross-team review** (FIM + IT Hygiene) — enforce via CODEOWNERS on that header.
