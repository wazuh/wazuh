# Inventory Sync Benchmark — Sender Reimplementation Requirements

This folder contains the functional specification for reimplementing
[`benchmark_sender.py`](../../benchmark_sender.py) in Go. It is **not** a tutorial;
it is a reference set that a Go developer can read to implement a drop-in
replacement that produces identical wire traffic, identical CSV/JSON output,
and identical scenario semantics.

## Table of contents

| #  | Document                                                             | What you find there                                              |
| -- | -------------------------------------------------------------------- | ---------------------------------------------------------------- |
| 00 | This file                                                            | Index, glossary, reading order                                   |
| 01 | [01-overview.md](./01-overview.md)                                   | What the sender is, why migrate, scope, I/O contract             |
| 02 | [02-functional-requirements.md](./02-functional-requirements.md)     | FR-1..FR-N + manager contract (status codes, safeguards)         |
| 03 | [03-scenario-schema.md](./03-scenario-schema.md)                     | Full JSON schema of scenario files + canonical examples          |
| 04 | [04-agent-state-machine.md](./04-agent-state-machine.md)             | Agent lifecycle + per-`session_type` state machines              |
| 05 | [05-wire-protocol.md](./05-wire-protocol.md)                         | Authd handshake + remoted framing + AES/zlib/MD5 stack           |
| 06 | [06-flatbuffers-messages.md](./06-flatbuffers-messages.md)           | FlatBuffer schema + builder/parser mapping per message type      |
| 07 | [07-concurrency-and-pacing.md](./07-concurrency-and-pacing.md)       | Python threads → Go goroutines, EPS pacing, parallel_agents      |
| 08 | [08-metrics-and-output.md](./08-metrics-and-output.md)               | `bench.csv` columns + `sender_summary.json` structure            |
| 09 | [09-error-handling-and-shutdown.md](./09-error-handling-and-shutdown.md) | Error matrix, SIGINT semantics, drain timeouts               |
| 10 | [10-go-implementation-notes.md](./10-go-implementation-notes.md)     | Libraries, code snippets, build & compatibility shim             |
| 11 | [11-acceptance-criteria.md](./11-acceptance-criteria.md)             | Parity tests + saturation tests + cutover checklist              |
| 12 | [12-engine-event-streams.md](./12-engine-event-streams.md)           | Engine-event payload type (Go-only): schema, wire, metrics       |

## Suggested reading order

- **Just want to understand the system** → 01 → 02 → 03.
- **Going to write the Go code** → all of them, but in particular 04–07 are the
  load-bearing technical pieces. 10 has the library recommendations.
- **Reviewing whether Go parity holds** → 11 + skim 08 for the output format.

## Glossary

- **Agent**: a simulated Wazuh agent. Each runs in its own goroutine (Python:
  thread). Owns one TCP socket to the manager.
- **Lane**: a sequence of steps a single agent runs. Within an agent, lanes
  run in parallel; within a lane, steps run sequentially.
- **Fleet**: a group of agents that share the same set of lanes. A scenario
  has either `total_agents` (one implicit fleet) or `fleets: [...]`.
- **Step**: one unit of work in a lane. Either a `dump` (replay a recorded
  session) or a `kind` (synthetic payload of a known shape).
- **Runner / SessionRunner**: the Python class that drives one step on one
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
- Pseudocode uses Go-flavoured syntax even when describing Python behaviour,
  because the target audience is the Go re-implementer.
- "MUST", "SHOULD", and "MAY" follow RFC 2119 sense.

## What is **NOT** in this set

- The orchestrator [`run_benchmark.sh`](../../run_benchmark.sh) and the monitor
  ([`monitor.py`](../../../../../engine/tools/devContainer/scripts/monitor.py)) are
  staying in bash/Python — no Go rewrite. They are documented elsewhere.
- The manager-side code (`inventorySyncFacade.hpp`, etc.) is out of scope
  beyond a short summary of the contract; see [02-functional-requirements.md](./02-functional-requirements.md).
- Charts and `result_summary.py` are unchanged — the Go sender just needs
  to write the same CSV/JSON shape so they keep working.
