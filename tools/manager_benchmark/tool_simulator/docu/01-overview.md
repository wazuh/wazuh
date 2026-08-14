# 01 — Overview

## What this measures

`inventory_sync_server` ingests agent state through ONE request per synchronization session: the
agent POSTs a FlatBuffers `Message{FullSession}` and the HTTP response IS the result. There are no
acknowledgment messages, no retransmission protocol and no session state — so the only meaningful
load question is **how many sessions of what size the manager sustains, at what latency, and which
status codes it starts returning when pushed**.

The sender exists to answer that with numbers, and to prove the contract holds under pressure
rather than only in unit tests: a `413` really is returned at the declared-size limit, a `503`
really carries `Retry-After` while the CVE feed downloads, two concurrent requests of one agent
really stay ordered.

## The two modes

The sender runs the SAME scenarios over two transports, and the difference between them is itself a
measurement — it isolates the cost of the relay:

### `--mode uds` — the server alone

Connects straight to the module's Unix socket (`queue/sockets/inventory-sync.sock`) and speaks the
bytes remoted would forward: `POST /stateful` with `X-Wazuh-Agent-Id`. No enrollment, no TLS, no
signing. This is the mode that measures the ingestion pipeline itself (validation, sharded workers,
group commit, the scan lane) with nothing else in the path.

### `--mode agent` — the whole path

Behaves like a fleet of real agents:

1. enrolls against authd (TCP/1515) to obtain an id and a key;
2. `POST /control` `startup` over HTTPS/1517, signed with AES-CMAC;
3. `POST /control` `notify` every 10 s per agent — the manager's real hot path;
4. `POST /stateful` sessions, relayed by remoted to the server;
5. optionally `POST /stateless` log-event batches, relayed by remoted to the engine (an *engine
   stream* lane — see [13-engine-event-streams.md](13-engine-event-streams.md)), so a scenario can
   put realistic event pressure on the manager at the same time as inventory;
6. `POST /control` `shutdown` on drain.

This mode measures what an operator actually experiences, and its delta against `uds` for identical
scenarios is the remoted relay overhead. It is also the only mode where a single agent runs several
lanes at once — several inventory modules plus a log stream — which is the realistic shape and the
one that stresses the manager's cross-lane paths (see [07](07-scenario-schema.md)).

## What the sender does NOT do

- **It does not interpret the manager's configuration.** `POST /control` answers with `limits`,
  `cluster`, `agent.groups`, `config_hash`, `settings_hash` and pending `tasks`. The sender
  **MUST** validate that response (status `200`, parseable JSON) and record its latency and size,
  and **MUST NOT** let any field of it change its behavior: no rate limit is adopted, no group is
  honored, no task is executed, no hash is compared. A benchmark whose load shape depends on the
  system under test cannot produce comparable numbers, and the tool is not a conformance checker
  for that payload. It still **MUST** send the keepalives themselves, because their traffic is
  precisely part of what is being measured.
- **It does not verify indexed documents.** Correctness of ingestion is the integration QA's job
  (`inventory_sync_server/qa/`, 52 tests). The sender asserts only what the protocol answers.
- **It does not retry on the agent's behalf.** Idempotent re-POST is the AGENT's retry contract, not
  a way to make a benchmark look better. The single exception is `503` + `Retry-After` for a feed
  still downloading (see FR-9), which is a start-up condition of the manager rather than load.
- **It does not tune the manager.** Preparing the manager (enrollment without a password, indexer
  reachable) belongs to the orchestration scripts, and every setting used is recorded with the run.

## Relationship to the retired simulator

The 4.x simulator (`wazuh_modules/inventory_sync/benchmark/tool_simulator/`) is the source of the
STRUCTURE reused here — package layout, stdlib `flag` CLI, per-second CSV plus a summary JSON,
scenario-driven runs. None of its wire survives: that tool spoke TCP/1514 with AES/zlib/MD5 framing
and a Start/Ack/ReqRet/End state machine over sequence numbers. All of that is gone from the
protocol, so those documents describe a system that no longer exists and are not a reference for
behavior.
