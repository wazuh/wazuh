# 05 — FlatBuffers messages

The body of every `/stateful` request is one `Message{FullSession}`. The schema is shared with the
manager: `src/shared_modules/utils/flatbuffers/schemas/inventorySync.fbs`, namespace
`Wazuh.SyncSchema`; the field-by-field reference is
`docs/ref/modules/inventory-sync-server/flatbuffers.md`.

## Generated bindings

The Go bindings **MUST** be generated from that schema at build time
(`flatc --go -o internal/fb <schema>`) and **MUST NOT** be committed. The retired simulator
committed its generated package and it silently drifted from the schema — regenerating is the only
way a schema change becomes a compile error instead of a wrong wire.

## The envelope

```text
Message { content: MessageType }        // root type
FullSession { start: Start, payload: SessionPayload }
union SessionPayload { SyncData, Cleans, ChecksumModule }
```

The sender **MUST** set `Message.content_type = FullSession`. Every other union member exists for
historical reasons and is answered `400` by the server; a scenario **MAY** send one deliberately to
measure the rejection path.

## Start

Built once per session from the scenario's agent identity plus its `start` block. Fields the sender
**MUST** fill:

| Field | Value |
|---|---|
| `agentid` | The agent's id. In `agent` mode it **MUST** equal the authenticated identity, or the answer is `403` |
| `cluster_name` | The manager's cluster name, from the run configuration (empty → `400`, mismatch → `403`) |
| `mode` | The scenario's mode (see the matrix below) |
| `option` | `Sync`, `VDFirst` or `VDSync` — this is what routes a data session to the scan lane |
| `index` | The indices the session targets. Required for the metadata/group modes, which have no payload |
| `module` | e.g. `syscollector`, `fim`, `sca` — recorded, and part of what the scenario describes |

The schema also has a `cluster_node`, and the sender **MUST NOT** set it. The manager never validated
it, its last consumer is being removed, and the only value that was ever correct for it is the
manager's own configured node name — which is precisely what the tool used to read out of the
manager's config and hand straight back. A real agent does not know it either: its `cluster_node` is
whatever the manager told it during the `/control` handshake
(`agent_metadata_t.cluster_node`, "received during handshake"). With stateless HTTPS the node that
processes a session need not even be the one that answered that handshake, so an agent-declared node
is at best redundant and at worst stale.

Fields that are metadata stamped onto documents (`agentname`, `agentversion`, `architecture`,
`hostname`, `osname`, `osplatform`, `ostype`, `osversion`, `groups`) **SHOULD** be filled with
plausible per-agent values: they inflate the session and are overlaid onto every document, so
omitting them makes payload sizes unrealistic. `global_version` **MUST** be set for the
metadata/group modes (it is the stale-writer guard).

`feed_offset` matters only when `option` is `VDFirst`/`VDSync`: the server rejects a mismatch
against its own current VD feed offset with `409 {"error":"version_mismatch","current_version":N}`
before the session ever reaches the scanner (see
[inventory_sync_server's flatbuffers.md](../../../../docs/ref/modules/inventory-sync-server/flatbuffers.md)).
The sender resolves it per VD step: the step's own `feed_offset` (scenario JSON) wins, then
`-vd-feed-offset` (CLI), then whatever `agent` mode's keepalive loop has learned from `/control`'s
`vd_feed_offset` (see [03-control-protocol.md](03-control-protocol.md)) -- which stays 0 forever in
`uds` mode, since there is no `/control` there to learn it from. A `uds`-mode VD scenario run
against a target whose feed has moved past offset 0 therefore needs `-vd-feed-offset` passed
explicitly, or every VD session gets the version_mismatch 409 instead of a real scan.

## Payload by mode

| `mode` | payload | What the scenario is measuring |
|---|---|---|
| `ModuleDelta` | `SyncData{values[], contexts[]}` | The bulk ingestion path: sharded workers, group commit. `values` **MUST** be ≥ 1 |
| `ModuleDelta` | `Cleans{items[]}` | Agent-scoped deletion by index; also the first half of a full resync |
| `ModuleCheck` | `ChecksumModule{index, checksum}` | The integrity path: a paged search plus a SHA-1 aggregate, the most read-heavy session there is |
| `MetadataDelta` / `MetadataCheck` | *(none)* | One update-by-query across the declared indices |
| `GroupDelta` / `GroupCheck` | *(none)* | Same, for group membership |

Anything outside that matrix is `400` before any I/O — cheap, and therefore useful only as a
deliberate rejection scenario.

There is **no `ModuleFull`**: a full resync is composed by the client as two ordinary sessions, a
`Cleans` of the module's indices followed by a `ModuleDelta` with the complete dataset (D19). The
sender **MUST** model it that way, and **SHOULD** send both on the same connection sequence so the
ordering guarantee (same agent → same shard → FIFO) is what is exercised.

## Documents

Each `DataValue` carries `operation` (`Upsert`/`Delete`), `id`, `index`, an optional `version`
(> 0 selects a versioned upsert) and `data`: the document as **JSON bytes**. The sender **MUST**
generate documents whose size is controlled by the scenario (payload-size knob) and **SHOULD** make
them realistic in shape for the target index. `checksum.hash.sha1` is **always** included (every real
agent document has one, and it is the field the manager aggregates for `ModuleCheck`); there is no
scenario knob to leave it out — see [07](07-scenario-schema.md#conventions).

`DataContext` items are the vulnerability-detection context: they are consumed by the scan lane and
never indexed as state documents. A VD scenario **SHOULD** include them, since they add bytes and
work without adding documents.

## What is NOT in the schema

No acknowledgments, no `End`, no per-item sequence numbers, no `ReqRet`, no session id. Re-POSTing
the identical buffer is idempotent, and that is the entire retry story. A sender that keeps
per-session state beyond "this request is in flight" is modeling a protocol that does not exist.
