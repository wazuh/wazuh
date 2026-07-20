# Inventory Sync Benchmark — Go Sender

This folder contains the design reference for the Go benchmark sender
(`cmd/benchmark_sender`). It covers the wire protocol, scenario schema,
concurrency model, metrics output, and error handling.

## Table of contents

| #  | Document                                                             | What you find there                                              |
| -- | -------------------------------------------------------------------- | ---------------------------------------------------------------- |
| 00 | This file                                                            | Index, glossary, reading order                                   |
| 01 | [01-overview.md](./01-overview.md)                                   | What the sender is, design rationale, scope, I/O contract            |
| 02 | [02-functional-requirements.md](./02-functional-requirements.md)     | FR-1..FR-N + manager contract (status codes, safeguards)             |
| 03 | [03-scenario-schema.md](./03-scenario-schema.md)                     | Full JSON schema of scenario files + canonical examples              |
| 04 | [04-agent-state-machine.md](./04-agent-state-machine.md)             | Agent lifecycle + per-`session_type` state machines                  |
| 05 | [05-wire-protocol.md](./05-wire-protocol.md)                         | Authd handshake + remoted framing + AES/zlib/MD5 stack               |
| 06 | [06-flatbuffers-messages.md](./06-flatbuffers-messages.md)           | FlatBuffer schema + builder/parser mapping per message type          |
| 07 | [07-concurrency-and-pacing.md](./07-concurrency-and-pacing.md)       | Goroutine layout, EPS pacing, parallel_agents                        |
| 08 | [08-metrics-and-output.md](./08-metrics-and-output.md)               | `bench.csv` columns + `sender_summary.json` structure                |
| 09 | [09-error-handling-and-shutdown.md](./09-error-handling-and-shutdown.md) | Error matrix, SIGINT semantics, drain timeouts               |
| 10 | [10-go-implementation-notes.md](./10-go-implementation-notes.md)     | Libraries, code snippets, build reference, CLI flags                 |
| 11 | [11-acceptance-criteria.md](./11-acceptance-criteria.md)             | Verification scenarios + test matrix                                 |
| 12 | [12-engine-event-streams.md](./12-engine-event-streams.md)           | Engine-event payload type: schema, wire, metrics                     |

## Suggested reading order

- **Just want to understand the system** → 01 → 02 → 03.
- **Extending or debugging the sender** → 04–07 are the load-bearing technical
  pieces. 10 has the library picks and build instructions.
- **Verifying correctness** → 11 + skim 08 for the output format.

## Glossary

- **Agent**: a simulated Wazuh agent. Each runs in its own goroutine.
  Owns one TCP socket to the manager.
- **Lane**: a sequence of steps a single agent runs. Within an agent, lanes
  run in parallel; within a lane, steps run sequentially.
- **Fleet**: a group of agents that share the same set of lanes. A scenario
  has either `total_agents` (one implicit fleet) or `fleets: [...]`.
- **Step**: one unit of work in a lane. Either a `dump` (replay a recorded
  session) or a `kind` (synthetic payload of a known shape).
- **Runner / SessionRunner**: the Go type that drives one step on one
  agent — sends `Start`, the data messages, and `End`; awaits acks.
- **Session**: the unit of work the manager tracks. Spans `Start → … → End`
  and carries a 64-bit session ID assigned by the manager in `StartAck`.
- **Dump**: a JSON file capturing a real inventory_sync session (metadata +
  ordered DataValue/DataContext/DataClean items). Replayed verbatim.
- **Kind**: a built-in synthetic payload type (`package`, `system`,
  `fim_file`, `sca_check`, …) generated from a template.
- **ReqRet**: the manager's "request retransmit" response — lists missing
  `seq` ranges; the sender resends those items if `retransmit=true`.
- **EPS**: events per second cap, per-session, leaky-bucket enforced.
- **Drain**: post-finish grace period where no new messages are sent but the
  sender keeps reading the socket and recording acks.

## Conventions used across the docs

- Code references use `[path:line](path#Lline)`-style links — they resolve in
  the GitHub UI.
- Wire-protocol bytes are shown in ASCII when printable; hex otherwise.
- Pseudocode uses Go syntax.
- "MUST", "SHOULD", and "MAY" follow RFC 2119 sense.

## What is **NOT** in this set

- The orchestrator [`run_benchmark.sh`](../../run_benchmark.sh) and the monitor
  ([`monitor.py`](../../../../../engine/tools/devContainer/scripts/monitor.py)) are
  in bash/Python. They are documented in the benchmark README.
- The manager-side code (`inventorySyncFacade.hpp`, etc.) is out of scope
  beyond a short summary of the contract; see [02-functional-requirements.md](./02-functional-requirements.md).
- [`result_summary.py`](../../result_summary.py) and
  `monitor_graphics_generator.py` consume `bench.csv` / `sender_summary.json`
  produced by the sender; their format is specified in [08](./08-metrics-and-output.md).
