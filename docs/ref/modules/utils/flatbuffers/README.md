# FlatBuffers

[FlatBuffers](https://flatbuffers.dev/) is the binary serialization format two manager
modules use: the inventory synchronization wire protocol between agents and the
[Inventory Sync Server](../../inventory-sync-server/README.md), and the
[Vulnerability Scanner](../../vulnerability-scanner/README.md)'s local feed database. A
reader accesses fields in place, without unpacking the buffer first.

## Schemas on the manager

| Schema (`.fbs`) | Location | Used by | For |
|---|---|---|---|
| `inventorySync.fbs` | `src/shared_modules/utils/flatbuffers/schemas/` | Inventory Sync Server (decodes); the agents' [sync protocol](../sync-protocol/README.md) (encodes); Vulnerability Scanner (its `Mode`/`Option` enums in the scan context) | The synchronization session on the wire |
| `cve5.fbs`, `packageTranslation.fbs`, `vulnerabilityCandidate.fbs`, `vulnerabilityDescription.fbs`, `vulnerabilityRemediations.fbs` | `src/wazuh_modules/vulnerability_scanner/schemas/` | Vulnerability Scanner | Feed records stored in its RocksDB database |

The headers are generated at build time by `flatc` (built from `src/external/flatbuffers`)
into `*_generated.h`, together with a `*_schema.h` that embeds the schema text; nothing
generated is committed.

## Inventory synchronization

A whole synchronization session travels as **one** `Message{FullSession}` in the body of
`POST /stateful` — the `Start` metadata plus the session's payload, with no
acknowledgments, no `End` message and no per-item sequence numbers. The HTTP response is
the session's result; there is no status enum in the schema. The session modes, the
payload tables, the pinned enum values and what the server validates are documented in
[Inventory Sync Server Schemas](../../inventory-sync-server/flatbuffers.md); the
statuses a session can end with, in the
[response contract](../../inventory-sync-server/api-reference.md#response-contract).

## Vulnerability Scanner feed

When the scanner processes its CVE feed, each `cve5` and `packageTranslation` resource
is parsed from JSON with the embedded schema, verified, and stored as a FlatBuffers
buffer in a column of the scanner's RocksDB database; the candidate, description and
remediation tables derived from it use the other three schemas. Scans then read those
records in place.
