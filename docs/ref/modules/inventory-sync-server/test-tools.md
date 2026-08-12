# Inventory Sync Server Test Tools

Four things live with the module's sources: a raw HTTP sender for the transport and routes, a
driver for the whole-agent deletion, a full integration driver that exercises the pipeline together
with the real vulnerability scanner (doubling as the QA suite's server harness), and the
integration QA suite itself.

## `tools/send_sync.py` — UDS smoke sender

A standard-library-only Python script (it runs on the manager's embedded interpreter without
installing anything) that speaks the same bytes remoted puts on the wire: HTTP/1.1 over an
`AF_UNIX` stream, `Content-Length` delimited, `Connection: close`. Useful to probe a live module
and to reproduce every transport-level rejection by hand.

Run it from the manager's home directory so the default relative socket path resolves, or pass
`--socket` with an absolute path.

```bash
# Liveness probe (expects 200)
./send_sync.py --health

# Junk payload to POST /stateful (expects 400: not a valid FullSession)
./send_sync.py --size 1024

# Missing identity header (expects 400)
./send_sync.py --agent-id ""

# Unknown route (404) and wrong verb (405 + Allow header)
./send_sync.py --bad-route
./send_sync.py --method PUT

# A session declaring more than the total in-flight budget (expects 413)
./send_sync.py --size 335544320

# 100 requests in sequence, to watch the throttled log lines aggregate
./send_sync.py --size 4096 --repeat 100 --quiet
```

Options: `--socket`, `--path` (default `/stateful`), `--method`, `--size`, `--repeat`,
`--content-type`, `--timeout`, `--agent-id` (the `X-Wazuh-Agent-Id` header remoted would set;
empty string omits it), `--health`, `--bad-route`, `--quiet`. The exit code is `0` only when every
response was a 2xx, so it can anchor a shell check.

Sending a VALID session requires a FlatBuffers `FullSession` body, which this script deliberately
does not build — that is the integration driver's job below.

## `tools/send_delete_agent.py` — whole-agent deletion driver

Same standard-library-only approach, aimed at `DELETE /agents`: it speaks the bytes **authd** puts
on the wire, so it exercises the real deletion rather than an approximation. The endpoint is
UDS-local (remoted has no downstream route to it), so this script is the only way to drive it by
hand.

The deletion covers the whole scope — `wazuh-states-*`, `wazuh-agent-config` and
`wazuh-agent-stats` — one delete-by-query per index. `--verify` counts the agent's documents on the
indexer before and after, which is the only way to see what the `200` actually did: the endpoint
answers the same `{"status":"ok"}` whether it deleted thousands of documents or none.

`--verify` refreshes the indices itself before counting, which is what makes its numbers meaningful:
the server does NOT refresh before its delete-by-query (see the
[deletion semantics](api-reference.md#whole-agent-deletion-semantics)), so a document the agent's
last session wrote inside the index refresh interval can survive a `200`. When `--verify` reports a
non-zero count after a successful deletion, that window — not a failed request — is the usual cause,
and re-running the deletion clears it.

```bash
# Delete agent 900; proves the UDS hop and the status, nothing more
./send_delete_agent.py --agent-id 900

# Count the agent's documents before and after (needs indexer certificates)
sudo ./send_delete_agent.py --agent-id 900 --verify

# Prove the deletion is per agent: 900 goes, 901 is untouched
sudo ./send_delete_agent.py --agent-id 900 --verify --witness 901

# The POST alias authd uses, because its HTTP helper only speaks POST
./send_delete_agent.py --agent-id 900 --alias

# Contract checks: missing and non-numeric ids (both expect 400)
./send_delete_agent.py --agent-id ''
./send_delete_agent.py --agent-id not-numeric
```

Options: `--socket`, `--agent-id`, `--alias`, `--timeout` (default 60 s — the deletion does indexer
I/O), `--verify`, `--witness`, `--indexer`, `--cert`, `--key`, `--client-keys`, `--force`.

Three guards worth knowing, all of them there because their absence produces a *reassuring* wrong
answer:

- **It refuses an agent that is enrolled in `client.keys`**, unless `--force`. Deleting a live
  agent's documents destroys inventory that only a full agent resync restores.
- **With `--verify`, it aborts when the indexer cannot be read** (bad certificates, indexer down)
  instead of reporting every count as zero.
- **It warns when the agent has no documents to begin with.** A deletion that answers `200` having
  found nothing proves nothing; seed first with `POST /config` and `POST /stats` (see
  `remoted_module/tools/send_agent_json.py`), and remember both write through the ASYNC connector,
  so wait for the documents to appear before deleting.

## `inventory_sync_server_testtool` — integration driver

The C++ driver behind the vulnerability-detection integration workflow
(`wazuh_modules/vulnerability_scanner/qa/test_efficacy_log.py`). It boots the REAL module pair —
the vulnerability scanner and this server, in one process — converts a JSON description into one
FlatBuffers `Message{FullSession}` per input file, and POSTs it to the server's real UDS socket
with the `X-Wazuh-Agent-Id` header, exactly as remoted would. Because a VD `200` guarantees
scan-then-ingest, the driver needs no scan-completion polling: the HTTP status IS the outcome.

Built as the `inventory_sync_server_testtool` CMake target (into `build/bin/`); sources in the
module's `testtool/` directory.

```text
inventory_sync_server_testtool <input.json>|<directory>
                               [--config <file>]        # module config: clusterName + <indexer> block
                               [--logFile <file>]       # scanner log lines, "function():message" format
                               [--wait <seconds>]       # settle time after the last session (default 3)
                               [--feed-timeout <secs>]  # how long to retry 503 feed-not-ready (default 300)
                               [--verbose]

inventory_sync_server_testtool --serve [--no-vd] [--config <file>] [--logFile <file>]   # QA harness mode
```

Behavior worth knowing:

- A `503` with `Retry-After` (the CVE feed still downloading) is retried, honoring the header,
  until `--feed-timeout` expires — so a test run can start before the feed finished seeding.
- A directory input processes every `*.json` in it, sorted, as one session each.
- The exit code is non-zero if any session did not answer `200`.
- `--serve` boots the module pair and keeps the socket open until SIGTERM/SIGINT instead of
  feeding inputs; `--no-vd` additionally skips the vulnerability scanner facade, which makes
  VD-flagged sessions resolve as the legitimate-skip row (index + `200`) with no CVE feed
  involved. This is how the integration QA gets a real server to talk to.

### Input format

```json
{
  "Start": {
    "agentid": "001",
    "option": "VDFirst | VDSync | Sync",      // default VDSync
    "mode": "delta",                           // default delta
    "agentname": "test-agent-001",             // every Start metadata field is optional,
    "agentversion": "5.0.0",                   // with sensible defaults
    "architecture": "x86_64",
    "hostname": "test-host",
    "osname": "Ubuntu", "osplatform": "ubuntu", "ostype": "linux", "osversion": "22.04",
    "groups": ["default"],
    "indices": ["wazuh-states-inventory-packages"],  // optional; inferred from the data if omitted
    "feed_offset": 12345                             // optional; VDFirst/VDSync only, see below
  },
  "data_values": [
    {
      "operation": "upsert | delete",
      "index": "wazuh-states-inventory-packages",    // optional; inferred from the payload shape
      "id": "document-id-1",
      "payload": { "package": { "...": "..." }, "checksum": { "...": "..." } }
    }
  ],
  "data_context": [
    { "index": "wazuh-states-inventory-system", "id": "os-1", "payload": { "host": { "...": "..." } } }
  ]
}
```

Index inference when `index` is omitted: a payload with `package.hotfix` maps to
`wazuh-states-inventory-hotfixes`, any other `package` to `wazuh-states-inventory-packages`, and a
`host` to `wazuh-states-inventory-system`.

`Start.feed_offset` matters only for `VDFirst`/`VDSync` sessions: the server rejects one whose
offset doesn't match this node's current VD feed offset with `409 version_mismatch` (see
[api-reference.md](api-reference.md)). When the input JSON omits it, the driver stamps the
scanner's ACTUAL current offset instead of leaving it at 0 — queried fresh immediately before
building each session, including on every retry of the `503`-feed-not-ready loop below, so a
session built while the feed was still downloading never goes stale by the time it is resent.
Set it explicitly only to deliberately exercise the mismatch path.

The `--config` file is the same JSON the QA suite uses (`qa/config.json`): a
`clusterName` (which the driver stamps into every session's `Start.cluster_name`, since the server
answers `403` on a cluster mismatch) and the `<indexer>` block with the hosts the module and the
scanner should reach.

## The integration QA (`qa/`)

`src/wazuh_modules/inventory_sync_server/qa/` is a pytest suite that drives the served module over
its real socket: it regenerates the Python FlatBuffers bindings from the shared schema, builds
`Message{FullSession}` buffers per scenario, POSTs them as remoted would, and asserts the FINAL
STATE in a real OpenSearch (documents, `_id` shape, the `wazuh.*` overlay) rather than protocol
acks. It covers the validation matrix and identity rejections, ingestion and per-document skips,
cleans and the composed full resync, checksum verification (including `search_after` pagination),
metadata/group reconciliation with the `global_version` guard, agent deletion, and the VD
legitimate-skip lane. `qa/README.md` documents how to run it locally; CI runs it in the
`5_testintegration_inventory-sync-server.yml` workflow.

## Load and performance (`tools/manager_benchmark/`)

Correctness lives in the QA above; load lives in `tools/manager_benchmark/` (plain path — outside
this book): a Go sender that reproduces the agent's wire over the module's UDS socket or through
remoted's relay. Its `contract_*` scenarios pin this module's `400`/`413`/`503` contracts under
pressure (including the admission-queue shed and the VD lane's capacity), its `real_*` scenarios
replay real captured payloads, and every run scrapes `GET /metrics` alongside the client-side
counters. `tools/manager_benchmark/README.md` and `SCENARIOS.md` are the entry points.

## See Also

- [API Reference](api-reference.md)
- [Schemas](flatbuffers.md)
- [Architecture](architecture.md)
