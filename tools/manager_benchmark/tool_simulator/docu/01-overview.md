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

Connects straight to the module's Unix socket (`queue/sockets/inventory-sync-http.sock`) and speaks the
bytes remoted would forward: `POST /stateful` with `X-Wazuh-Agent-Id`. No enrollment, no TLS, no
signing. This is the mode that measures the ingestion pipeline itself (validation, sharded workers,
group commit, the scan lane) with nothing else in the path.

### `--mode agent` — the whole path

Behaves like a fleet of real agents:

1. enrolls over remoted's `POST /enroll` with an enrollment token to obtain an id and a key — the
   fleet's bootstrap, which needs no change to the manager's enrollment policy (`--bootstrap 1515`
   uses authd's legacy TCP listener instead, for comparing the two; see
   [16-enroll-https.md](16-enroll-https.md));
2. `POST /control` `startup` over HTTPS/1517, authenticated with a `wazuh-agent+jwt` bearer token
   (steps 2, 3 and 7 only when the scenario sets `defaults.control.enabled`; the readiness probe
   that waits for remoted to load the fleet's keys sends one `startup` either way);
3. `POST /control` `notify` per agent, every 10 s by default — the manager's real hot path;
4. `POST /stateful` sessions, relayed by remoted to the server;
5. optionally `POST /stateless` log-event batches, relayed by remoted to the engine (an *engine
   stream* lane — see [13-engine-event-streams.md](13-engine-event-streams.md)), so a scenario can
   put realistic event pressure on the manager at the same time as inventory;
6. optionally the other agent-facing requests a scenario step can send: `POST /scan/vd`
   ([14](14-scan-vd.md)), `GET /cacerts` ([15](15-cacerts.md)) and `POST /enroll` of a fresh name
   ([16](16-enroll-https.md));
7. `POST /control` `shutdown` once the agent's lanes finish (or on drain).

This mode measures what an operator actually experiences, and its delta against `uds` for identical
scenarios is the remoted relay overhead. It is also the only mode where a single agent runs several
lanes at once — several inventory modules plus a log stream — which is the realistic shape and the
one that stresses the manager's cross-lane paths (see [07](07-scenario-schema.md)).

## What the sender does NOT do

- **It does not interpret the manager's configuration.** `POST /control` answers with `limits`,
  `cluster`, `agent.groups`, `config_hash`, `settings_hash`, `ca_generation`, `vd_feed_offset` and
  pending `tasks`. The sender **MUST** validate that response (status `200`, parseable JSON) and
  record its latency and size, and **MUST NOT** let any field of it change its behavior: no rate
  limit is adopted, no group is honored, no task is executed, no hash is compared. The one
  exception is `vd_feed_offset`, which VD sessions must echo (see
  [03](03-control-protocol.md#what-the-sender-does-with-the-response)). A benchmark whose load shape depends on the
  system under test cannot produce comparable numbers, and the tool is not a conformance checker
  for that payload. It still **MUST** send the keepalives themselves, because their traffic is
  precisely part of what is being measured.
- **It does not verify indexed documents.** Correctness of ingestion is the integration QA's job
  ([`inventory_sync_server/qa/`](../../../../src/wazuh_modules/inventory_sync_server/qa/README.md)).
  The sender asserts only what the protocol answers.
- **It retries a `/stateful` session only the way an agent does.** Two answers are re-sent. One is
  `503` + `Retry-After` for a feed still downloading (FR-11), which is a start-up condition of the
  manager rather than load. The other is a bare `503` (backpressure), re-sent per the scenario's
  `defaults.retry` block (on by default: 500 ms apart, 10 attempts), because that is what a real
  agent does. Every attempt is counted and paced, and shed-counting scenarios switch it off. No
  other answer, and no other route, is ever retried. FR-12 as first written said "never retry a
  bare `503`"; see the note there.
- **It does not tune the manager.** Preparing the manager (remote enrollment reachable, a token
  minted, indexer reachable) belongs to the orchestration scripts, and every setting used is
  recorded with the run. It no longer WEAKENS the manager either: the default bootstrap runs against
  the installed `<use_password>` policy.

## Relationship to the retired simulator

The 4.x simulator (`wazuh_modules/inventory_sync/benchmark/tool_simulator/`, no longer in this
tree) is the source of the
STRUCTURE reused here — package layout, stdlib `flag` CLI, per-second CSV plus a summary JSON,
scenario-driven runs. None of its wire survives: that tool spoke TCP/1514 with AES/zlib/MD5 framing
and a Start/Ack/ReqRet/End state machine over sequence numbers. All of that is gone from the
protocol, so those documents describe a system that no longer exists and are not a reference for
behavior.
