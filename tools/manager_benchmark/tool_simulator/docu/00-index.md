# benchmark_sender — design documentation

Design set for the load-generation tool of `inventory_sync_server`. It is written **before** the
implementation: F9c-2 implements against these documents, so a disagreement between code and
document is a bug in one of them, to be resolved rather than tolerated.

Requirement levels follow RFC 2119: **MUST**, **MUST NOT**, **SHOULD**, **MAY**.

## Reading order

| Doc | Read it for |
|---|---|
| [01-overview.md](01-overview.md) | What the tool measures, its two modes, and what it deliberately does not do |
| [02-functional-requirements.md](02-functional-requirements.md) | The HTTP contract the sender must honor (FR-1…FR-14) |
| [03-control-protocol.md](03-control-protocol.md) | `POST /control`: startup, keepalives, shutdown — shapes, auth, cadence |
| [04-wire-protocol.md](04-wire-protocol.md) | Enrollment, the AES-CMAC canonical string, HTTPS and UDS transports |
| [05-flatbuffers-messages.md](05-flatbuffers-messages.md) | Building `Message{FullSession}` from a scenario |
| [06-agent-state-machine.md](06-agent-state-machine.md) | The simulated agent's lifecycle and the (stateless) session lifecycle |
| [07-scenario-schema.md](07-scenario-schema.md) | The scenario JSON schema |
| [08-concurrency-and-pacing.md](08-concurrency-and-pacing.md) | Goroutine model, EPS pacing, deliberate saturation |
| [09-metrics-and-output.md](09-metrics-and-output.md) | **The** definition of the output artifacts |
| [10-error-handling-and-shutdown.md](10-error-handling-and-shutdown.md) | Error matrix, drain, what fails a run |
| [11-go-implementation-notes.md](11-go-implementation-notes.md) | Libraries and package layout |
| [12-acceptance-criteria.md](12-acceptance-criteria.md) | AC-A…AC-L: when the tool is done |
| [13-engine-event-streams.md](13-engine-event-streams.md) | `POST /stateless`: the log-event batch a lane can stream, alongside inventory |
| [14-scan-vd.md](14-scan-vd.md) | `POST /scan/vd`: the feed-update re-scan request, and how it differs from a VDFirst session's scan |

Operator-facing documentation of the system under test lives in
`docs/ref/modules/inventory-sync-server/` (architecture, API reference, schemas) and
`docs/ref/modules/remoted/`. This set documents the **client**, and cites those where the contract
originates.

## Glossary

| Term | Meaning here |
|---|---|
| **Sender** | The `benchmark_sender` binary: the whole load generator |
| **Mode** | Which transport the run exercises: `uds` (the server alone) or `agent` (through remoted) |
| **Agent** | One simulated agent: an identity (id + key), a keepalive loop, and its fleet's lanes running in parallel |
| **Fleet** | A group of agents (usually `bench-<n>`) that share a lane set and a metadata profile — a run may have several (a Windows fleet and a Linux fleet at once) |
| **Lane** | A named, ordered list of steps one agent runs. An agent runs all of its fleet's lanes **in parallel** (FIM, SCA, syscollector, VD, engine…), the way a real agent does |
| **Scenario** | A JSON file describing a run: mode, lanes, fleets, pacing |
| **Session** | ONE `POST /stateful` request carrying one whole `Message{FullSession}`, and its response |
| **Keepalive** | A `POST /control` of type `notify`, sent periodically per agent (default every 10 s) |
| **Engine stream** | A lane that ships log events to `POST /stateless` (the engine ingress) instead of inventory sessions |
| **Re-scan request** | A `POST /scan/vd` (`kind: "scan_vd"`): asks the manager to re-scan the inventory it ALREADY holds for that agent, against a newer CVE feed — not the scan a VDFirst/VDSync session triggers over the inventory it carries |
| **EPS** | Requests per second the sender aims for, enforced by a leaky bucket |
| **Drain** | The bounded shutdown window: stop starting work, let in-flight responses land, then report |
| **Artifacts** | The files a run produces: `bench.csv`, `sender_summary.json`, `server_metrics.csv`, … |

## What is NOT here

The orchestration scripts (`run_benchmark.sh`, the resource monitor, the chart generators) and the
scenario corpus are F9c-3; the load report is F9c-4. This set covers only the sender itself.
