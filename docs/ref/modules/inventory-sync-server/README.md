# Inventory Sync Server Module

Manager-side synchronization service for agent state data, exposed over an HTTP/1.1 Unix domain
socket (`queue/sockets/inventory-sync.sock`) by `wazuh-manager-modulesd`. A whole synchronization
session travels as ONE FlatBuffers `Message{FullSession}` request through
[Remoted](../remoted/README.md)'s authenticated `POST /stateful` route, and the HTTP response
relayed back to the agent IS the session result — no acks, no retransmission, no session store.

## Key Features

- **One request = one session** (`FullSession`): delta data, cleans, integrity checksums, and
  metadata/group reconciliation, all answered synchronously with the contract's status codes
  (`200` ok/noop, `400`, `403` identity mismatch, `409` checksum mismatch (or `version_mismatch`
  for a VDFirst/VDSync session whose `feed_offset` is stale), `413` over budget, `500` failed with
  nothing indexed, `503` + optional `Retry-After`).
- **Per-agent ordering by construction**: sessions are applied by workers sharded on the agent id
  (one indexer connector per worker, group-commit bulk flushes), so two requests of the same agent
  can never be reordered.
- **Synchronous vulnerability scanning**: sessions with option `VDFirst`/`VDSync` run through a
  dedicated scan lane that executes the [Vulnerability Scanner](../vulnerability-scanner/README.md)
  BEFORE indexing — a `200` guarantees the scan ran AND the inventory was flushed; a failed scan
  answers `500` with nothing indexed; a still-downloading CVE feed answers `503 + Retry-After`
  without processing.
- **Agent deletion endpoint** (`DELETE /agents`, plus a `POST /agents/delete` alias for C callers):
  UDS-local, called by `wazuh-manager-authd` when an agent is removed. It reaches every index holding
  the agent's documents — `wazuh-states-*` plus `wazuh-agent-config` and `wazuh-agent-stats` — and
  issues one delete-by-query per index. The deletion defers to the agent's worker shard, so it
  orders correctly against in-flight sessions of that same agent, and the HTTP status makes a lost
  deletion visible instead of silent.
- HTTP/1.1 over a Unix domain socket, so no TCP port is exposed; admission control before a body is
  read (in-flight byte budget, connection cap); two-phase shutdown; the socket does not open until
  the indexer session and connectors are constructed successfully.

## Components

- [Architecture](architecture.md) - the request pipeline, the sync workers, the vulnerability
  scan lane, agent deletion, transport, startup gate, shutdown, and the design decisions
- [API Reference](api-reference.md) - the routes, their statuses and their bodies
- [Configuration](configuration.md) - the internal options, their ranges and their defaults
- [Schemas](flatbuffers.md) - the FullSession FlatBuffers contract
- [Test Tools](test-tools.md) - the UDS drivers (smoke sender, agent-deletion driver), the
  integration test driver and the QA suite

## Routes

| Route | Caller | Purpose |
| --- | --- | --- |
| `POST /stateful` | Remoted (relaying agents) | Apply one whole synchronization session |
| `DELETE /agents` / `POST /agents/delete` | authd | Delete every document of an agent, across `wazuh-states-*`, `wazuh-agent-config` and `wazuh-agent-stats` |
| `POST /stats`, `POST /config` | Remoted (relaying agents) | Agent stats/config documents |
| `GET /` | anyone local | Liveness probe |
| `GET /metrics` | anyone local (operators, the benchmark harness) | Runtime statistics as JSON |

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

## What flows through it (use cases)

Five agent-side producers feed this one pipeline: **Syscollector** (hardware, OS, packages,
processes, ports, networks, users, groups, services... → `wazuh-states-inventory-*`),
**Syscollector's VD sessions** (the package/OS data that drives vulnerability detection), **FIM**
(files and Windows registry → `wazuh-states-fim-*`), **SCA** (policy checks →
`wazuh-states-sca`), and **agent-info** (metadata and group membership reconciliation across the
agent's documents). The situations an operator will recognize:

- **First connection**: the agent sends each module's full state — large single sessions (a
  Windows FIM registry corpus can be one ~26 MB session, which is what remoted's zstd request
  compression exists for).
- **Steady state**: small periodic deltas per module.
- **Checksum reconciliation**: the agent periodically sends a checksum-of-checksums
  (`ModuleCheck`); a `409` answer tells it to full-resync that module.
- **Full resync**: two ordinary requests — clean the module's indices, then re-send the full
  dataset. Their order is guaranteed by the per-agent worker shard.
- **Agent deletion**: authd calls `DELETE /agents` when an agent is removed, purging every document
  of that agent across `wazuh-states-*`, `wazuh-agent-config` and `wazuh-agent-stats` (this is why
  deleting an agent also removes its data from the dashboard).

## FAQ (operations)

- **Why am I seeing `503`s under load?** Four gates shed on purpose rather than queueing
  unboundedly: the connection cap, the in-flight byte budget, the pipeline's admission queue, and
  the VD lane's capacity — see the
  [503 troubleshooting entry](configuration.md#requests-are-answered-503-under-load) for which
  option matches which gate. Sheds are expected backpressure: agents retry on their own.
- **What does `Retry-After` mean?** Only one `503` carries it: the CVE feed is still downloading,
  so vulnerability-detection sessions are rejected *without processing* and the agent re-sends
  the same session after the given seconds. No other `503` schedules the retry for the agent.
- **Why did an agent full-resync out of nowhere?** Its `ModuleCheck` answered `409` — the
  manager-side checksum of that module's documents did not match the agent's. The resync is the
  repair, not the problem.
- **I deleted an agent and its documents are still in the indexer.** Look for a `WARNING` from
  `wazuh-manager-authd` naming that agent: authd retries the deletion three times and, if it never
  gets a `200`, says so and leaves the documents in place — with the agent gone from `client.keys`
  nothing else ever overwrites them. (A warning and not an error because the agent itself is gone and
  cannot reconnect; the leftover is orphaned data, not a broken manager.) Fix what the ERROR points at (an unhealthy indexer, or modulesd
  not listening on the socket) and repeat the deletion; it is idempotent, so re-running it is always
  safe. Two narrower causes leave no ERROR behind: a `POST /config` or `POST /stats` report that was
  still queued in the asynchronous connector when the deletion ran lands afterwards and recreates
  that one document, and the same repeat clears it. `inventory_sync_server/tools/send_delete_agent.py
  --verify` counts the agent's documents before and after, which is the quickest way to see what a
  `200` actually did.
- **Where are the metrics?** `GET /metrics` on the module's socket, UDS-local (agents can never
  reach it): `curl -s --unix-socket /var/wazuh-manager/queue/sockets/inventory-sync.sock
  http://localhost/metrics`. Shard depths/bytes tell you whether load is skewed;
  `sync.pipeline.shed.total` counts admission-queue sheds; `vd.lane.*` covers the scan lane. See
  the [API reference](api-reference.md#get-metrics).
- **What should I tune first?** If the admission queue sheds while CPUs sit idle, raise
  `sync_workers` — the queue (`sync_queue_bytes`) is a buffer, not throughput. Raise the byte
  budget or the connection cap only when those specific gates are the ones logging. Every option:
  [configuration](configuration.md).

## Related Modules

- [Remoted](../remoted/README.md) - relays agent sessions to this module.
- [Vulnerability Scanner](../vulnerability-scanner/README.md) - executed synchronously by the scan
  lane for VD sessions; coordinates feed-update scans through a shared per-agent registry.
- [Keystore](../keystore/README.md) - the encrypted credential store the indexer connectors read.
- [Indexer Connector](../indexer_connector/README.md) - the library used to reach the indexer.

## Development

Two in-repo companions to these pages (plain paths — they live outside this book):

- `src/wazuh_modules/inventory_sync_server/README.md` — the developer's map of the module: the
  functional/non-functional requirements catalog, the full set of design decisions (D1–D22), the
  annotated schema, the developer FAQ, and where to touch what.
- `tools/manager_benchmark/` — the load harness: the same wire as a real fleet over UDS or
  through remoted, the `contract_*` scenarios that pin this module's `400`/`413`/`503` contracts,
  and real captured payloads for production-shaped sessions.
