# 05 — FlatBuffers messages

The body of every `/stateful` request is one `Message{FullSession}`. The schema is shared with the
manager: `src/shared_modules/utils/flatbuffers/schemas/inventorySync.fbs`, namespace
`Wazuh.SyncSchema`; the field-by-field reference is
[`flatbuffers.md`](../../../../docs/ref/modules/inventory-sync-server/flatbuffers.md).

## Generated bindings

The Go bindings **MUST** be generated from that schema at build time
(`make generate`, which runs `$(FLATC) --go -o internal/fb <schema>`, `FLATC` defaulting to the
dependency tree's `src/external/flatbuffers/build/flatc`) and **MUST NOT** be committed
(`internal/fb/` is gitignored). The retired simulator
committed its generated package and it silently drifted from the schema — regenerating is the only
way a schema change becomes a compile error instead of a wrong wire.

## The envelope

```text
Message { content: MessageType }        // root type
FullSession { start: Start, payload: SessionPayload }
union SessionPayload { SyncData, Cleans, ChecksumModule }
```

The sender always sets `Message.content_type = FullSession` (`internal/fbbuild/session.go`). Every
other union member exists for historical reasons and is answered `400` by the server; the sender
cannot build one. The rejection paths it can exercise are the `raw` step's non-FlatBuffers bodies
([07](07-scenario-schema.md#step-kinds)).

## Start

Built per session from the agent's identity, the step, `defaults` and the fleet's `start` block
(`startFor()` in `internal/runner/helpers.go`). An empty string field is left out of the buffer.

| Field | Value |
|---|---|
| `agentid` | The agent's id: the one enrollment returned in `agent` mode (it **MUST** equal the authenticated identity, or the answer is `403`), `first_id + i` in `uds` mode |
| `cluster_name` | `--cluster`, else `defaults.cluster_name`. Both empty leaves the field out, and the server answers `400`; a foreign name is `403` |
| `mode` | Set by the step kind (see the matrix below) |
| `option` | The step's `option`, else `defaults.option`, else a dump's own: `VDFirst`/`vdfirst` and `VDSync`/`vdsync` select those, `Sync`/`sync` or absent builds `Sync`. The loader refuses any other value on a step or in `defaults`; a dump's own option is not checked at load, and an unrecognized one there builds `Sync`. This is what routes a data session to the scan lane |
| `index` | The step's `indices`, else a dump's own; left out when neither has any. Required by the loader for the metadata/group modes, which have no payload |
| `module` | The step's `module`, else `defaults.module`, else a dump's own — e.g. `syscollector`, `fim`, `sca` |

There is no cluster node in `Start`. The schema used to carry a `cluster_node`, which the manager
never validated and whose only correct value was the manager's own node name, so the sender used to
read it from the manager's config and hand it straight back. The field is gone from both the schema
and the agent's `agent_metadata_t`, and a scenario that still declares `defaults.cluster_node` is
refused at load time (unknown field).

Fields that are metadata stamped onto documents (`agentname`, `agentversion`, `architecture`,
`hostname`, `osname`, `osplatform`, `ostype`, `osversion`, `groups`) **SHOULD** be filled with
plausible per-agent values: they inflate the session and are overlaid onto every document, so
omitting them makes payload sizes unrealistic. The sender fills `agentversion`, `architecture`,
`osname`, `osplatform`, `ostype` and `osversion` from the fleet's `start` block, falling back to
`5.0.0`, `x86_64`, `Ubuntu`, `ubuntu`, `linux` and `22.04`; `hostname` and `agentname` are the
agent's name, and `groups` is always `["default"]`. `global_version` **MUST** be set for the
metadata/group modes (it is the stale-writer guard). The sender takes it from the step's
`global_version`; the loader does not require it, and a step that leaves it out (or sets `0`)
sends none.

`feed_offset` matters only when `option` is `VDFirst`/`VDSync`: the server rejects a mismatch
against its own current VD feed offset with `409 {"error":"version_mismatch","current_version":N}`
before the session ever reaches the scanner (see
[inventory_sync_server's flatbuffers.md](../../../../docs/ref/modules/inventory-sync-server/flatbuffers.md)).
The sender resolves it per VD session (`feedOffsetFor()` in `internal/runner/agent.go`): the
step's own `feed_offset` (scenario JSON, `0` included) wins, then `--vd-feed-offset` when non-zero,
then whatever `agent` mode's keepalive loop has learned from `/control`'s `vd_feed_offset` (see
[03-control-protocol.md](03-control-protocol.md)). In that last case, with control enabled, the
session first waits for this agent's first successful `notify`, up to 30 s, so a VD step at the
start of a lane does not race it and declare `0`. Without control — always in `uds` mode — nothing
is learned and the offset stays `0`. A `uds`-mode VD scenario run against a target whose feed has
moved past offset 0 therefore needs `--vd-feed-offset` passed explicitly, or every VD session gets
the version_mismatch 409 instead of a real scan. An offset of `0` is left out of the buffer (the
schema default). A dump that declares `VDFirst`/`VDSync` itself gets its offset resolved the same
way.

## Payload by mode

| `mode` | payload | What the scenario is measuring |
|---|---|---|
| `ModuleDelta` | `SyncData{values[], contexts[]}` | The bulk ingestion path: sharded workers, group commit. `values` **MUST** be ≥ 1: a `delta` with neither a `documents` spec nor `defaults.documents` (and no `dump`) sends an empty `values` vector, the server's rejection path |
| `ModuleDelta` | `Cleans{items[]}` | Agent-scoped deletion by index; also the first half of a full resync |
| `ModuleCheck` | `ChecksumModule{index, checksum}` | The integrity path: a paged search plus a SHA-1 aggregate, the most read-heavy session there is |
| `MetadataDelta` / `MetadataCheck` | *(none)* | One update-by-query across the declared indices. The sender builds only `MetadataDelta` (`kind: "metadata"`) |
| `GroupDelta` / `GroupCheck` | *(none)* | Same, for group membership. The sender builds only `GroupDelta` (`kind: "groups"`) |

Anything outside that matrix is `400` before any I/O — cheap, and therefore useful only as a
deliberate rejection scenario.

There is **no `ModuleFull`**: a full resync is composed by the client as two ordinary sessions, a
`Cleans` of the module's indices followed by a `ModuleDelta` with the complete dataset (D19). The
sender models it that way (`kind: "full_resync"`): both sessions go out on the same lane, the
`Delta` only after the `Cleans` answer has arrived, so the ordering guarantee (same agent → same
shard → FIFO) is what is exercised. (A dump's own `metadata.mode` — some captures say
`ModuleFull` — is ignored.)

## Documents

Each `DataValue` carries `operation` (`Upsert`/`Delete`), `id`, `index`, an optional `version`
(> 0 selects a versioned upsert) and `data`: the document as **JSON bytes**. The two sources
(`internal/source/`):

- **Generated** (`documents: {count, size_bytes}`): `count` `Upsert`s without `version`, all on the
  step's first index (`wazuh-states-inventory-packages` when it has none), ids
  `<agentid>-<lane>-<module>-<n>`. Each document is one index-shaped object — `file` for
  `wazuh-states-fim-files`, `check` for `wazuh-states-sca`, `package` for every other index — whose
  `path` or `description` carries a filler of `size_bytes` characters, plus
  `checksum.hash.sha1` (the SHA-1 of `<seed>:<id>`). The checksum is **always** included (every
  real agent document has one, and it is the field the manager aggregates for `ModuleCheck`); there
  is no scenario knob to leave it out — see [07](07-scenario-schema.md#conventions).
- **Replayed** (`dump`): every recorded item verbatim — its `operation`, `index`, `version` and
  `data` — with the id prefixed `<agentid>-` ([07](07-scenario-schema.md#replaying-real-payloads)).

`DataContext` items are the vulnerability-detection context: they are consumed by the scan lane and
never indexed as state documents. A step's `contexts: {count, size_bytes}` adds that many, generated
like documents (same index, ids `<agentid>-<lane>-<module>-ctx-<n>`); they add bytes and work
without adding documents.

## What is NOT in the schema

No acknowledgments, no `End`, no per-item sequence numbers, no `ReqRet`, no session id. Re-POSTing
the identical buffer is idempotent, and that is the entire retry story. A sender that keeps
per-session state beyond "this request is in flight" is modeling a protocol that does not exist.
