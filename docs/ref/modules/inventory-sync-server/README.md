# Inventory Sync Server Module

Manager-side synchronization service for agent state data, exposed over an HTTP/1.1 Unix domain
socket (`queue/sockets/inventory-sync.sock`) by `wazuh-manager-modulesd`. A whole synchronization
session travels as ONE FlatBuffers `Message{FullSession}` request through
[Remoted](../remoted/README.md)'s authenticated `POST /stateful` route, and the HTTP response
relayed back to the agent IS the session result — no acks, no retransmission, no session store.

## Key Features

- **One request = one session** (`FullSession`): delta data, cleans, integrity checksums, and
  metadata/group reconciliation, all answered synchronously with the contract's status codes
  (`200` ok/noop, `400`, `403` identity mismatch, `409` checksum mismatch, `413` over budget,
  `500` failed with nothing indexed, `503` + optional `Retry-After`).
- **Per-agent ordering by construction**: sessions are applied by workers sharded on the agent id
  (one indexer connector per worker, group-commit bulk flushes), so two requests of the same agent
  can never be reordered.
- **Synchronous vulnerability scanning**: sessions with option `VDFirst`/`VDSync` run through a
  dedicated scan lane that executes the [Vulnerability Scanner](../vulnerability-scanner/README.md)
  BEFORE indexing — a `200` guarantees the scan ran AND the inventory was flushed; a failed scan
  answers `500` with nothing indexed; a still-downloading CVE feed answers `503 + Retry-After`
  without processing.
- **Agent deletion endpoint** (`DELETE /agents`, plus a `POST /agents/delete` alias for C callers):
  UDS-local, called by `wazuh-manager-authd` when an agent is removed; the deletion defers to the
  agent's worker shard, so it orders correctly against in-flight sessions of that same agent, and
  the HTTP status makes a lost deletion visible instead of silent.
- HTTP/1.1 over a Unix domain socket, so no TCP port is exposed; admission control before a body is
  read (in-flight byte budget, connection cap); two-phase shutdown; the socket does not open until
  the indexer session and connectors are constructed successfully.

## Components

- [Architecture](architecture.md) - the request pipeline, the sync workers, the vulnerability
  scan lane, agent deletion, transport, startup gate, shutdown, and the design decisions
- [API Reference](api-reference.md) - the routes, their statuses and their bodies
- [Configuration](configuration.md) - the internal options, their ranges and their defaults
- [Schemas](flatbuffers.md) - the FullSession FlatBuffers contract
- [Test Tools](test-tools.md) - the UDS smoke sender and the integration test driver

## Routes

| Route | Caller | Purpose |
| --- | --- | --- |
| `POST /stateful` | Remoted (relaying agents) | Apply one whole synchronization session |
| `DELETE /agents` / `POST /agents/delete` | authd | Delete every state document of an agent |
| `POST /stats`, `POST /config` | Remoted (relaying agents) | Agent stats/config documents |
| `GET /` | anyone local | Liveness probe |

## Overview

1. An agent POSTs a whole session to `wazuh-manager-remoted` over authenticated HTTPS
   (`POST /stateful`, AES-CMAC per agent).
2. Remoted forwards the FlatBuffer verbatim to this module's Unix socket, adding the authenticated
   agent id as the `X-Wazuh-Agent-Id` header.
3. This module verifies the buffer, cross-checks the session's identity against that header (`403`
   on mismatch) and against this manager's cluster name, and applies the session on the agent's
   worker shard — through the vulnerability scan lane first when the session asks for it.
4. The response travels back through Remoted to the agent as its own HTTP response: `200` means
   applied AND flushed to the indexer (and scanned, for VD sessions); any other status tells the
   agent exactly what to do next (retry, resync, or fix the request).

## Related Modules

- [Remoted](../remoted/README.md) - relays agent sessions to this module.
- [Vulnerability Scanner](../vulnerability-scanner/README.md) - executed synchronously by the scan
  lane for VD sessions; coordinates feed-update scans through a shared per-agent registry.
- [Keystore](../keystore/README.md) - the encrypted credential store the indexer connectors read.
- [Indexer Connector](../indexer_connector/README.md) - the library used to reach the indexer.
