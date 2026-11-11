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

The headers are generated at build time by `flatc` (built from `src/external/flatbuffers`,
the FlatBuffers release pinned in `src/deps.lock.mk` — 23.5.26 at this writing) into
`*_generated.h`, together with a `*_schema.h` that embeds the schema text as a C++ string.
`inventorySync` lands in the gitignored `include/` directory under `src/shared_modules/utils/flatbuffers`, the
scanner's five in its build directory; nothing generated is committed. The agent compiles
the same `inventorySync.fbs` for its sync protocol, with `--scoped-enums`.

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
is parsed from JSON by a `flatbuffers::Parser` loaded with the embedded schema text and
stored as a FlatBuffers buffer in a column of the scanner's RocksDB database (an update
re-reads the stored buffer, patches it as JSON and re-parses it); the candidate,
description and remediation records derived from each `cve5` entry use the other three
schemas. Every read verifies the buffer (`flatbuffers::Verifier`) before a scan accesses
it in place. The tables and fields are documented in the
[Vulnerability Scanner schemas](../../vulnerability-scanner/flatbuffers.md).
