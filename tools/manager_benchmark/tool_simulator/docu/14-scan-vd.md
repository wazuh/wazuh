# 14 — The VD re-scan request (`POST /scan/vd`)

`/scan/vd` is the second, and completely separate, way a scan reaches the Vulnerability Detection
module. Getting the two confused makes a scenario measure something other than what it says, so the
distinction comes first:

| | VDFirst / VDSync `/stateful` session | `POST /scan/vd` |
|---|---|---|
| What it carries | The inventory itself (packages, system, hotfixes) | Nothing but `type` + `feed_offset` (4 KiB body cap) |
| What is scanned | The inventory in **that** session | The inventory the manager **already** holds for that agent |
| Manager-side path | `inventory_sync_server`'s VD scan lane (`src/vd/vdScanLane.cpp`) | remoted's own worker pool (`src/scanvd/scanVdHandler.cpp`) → `POST /vulnerability-detector/scan` over the modulesd UDS |
| When a real agent does it | On connect, and on every inventory change | When a `/control` notify reports a `vd_feed_offset` **higher** than the one it last synced against |
| Sender step | `delta` / `full_resync` with `option: VDFirst`/`VDSync` (or a dump that declares it) | `kind: "scan_vd"` |

Both validate the offset against the **same** source of truth
(`DatabaseFeedManager::getLastOffset()`, surfaced over UDS as `GET /vulnerability-detector/offset`
and cached ~30 s by remoted's `VdClient`), so a stale offset is rejected the same way on either
path — see [05-flatbuffers-messages.md](05-flatbuffers-messages.md) for the session side.

Source of truth: `src/remoted/remoted_module/src/endpoints/scanVdEndpoint.cpp` and
`src/remoted/remoted_module/src/scanvd/scanVdHandler.cpp`; the contract prose lives in
[remoted's https-events-api.md](../../../../docs/ref/modules/remoted/https-events-api.md#scan-endpoint-post-scanvd).

## Authentication

The same authenticated gateway as `/control` and `/stateful`: `protocol-version: 1` plus
`Authorization: Wazuh <agent-id>:<ts>:<cmac-hex>` over the target `/scan/vd` and the exact body
bytes ([04-wire-protocol.md](04-wire-protocol.md)). The agent id is the one in the header; the body
has no identity field. **agent mode only** — the module's Unix socket has no such route, so a `uds`
scenario carrying a `scan_vd` step is refused at load time, exactly like an `engine` step is.

## Request

```json
{"type": "feed_update", "feed_offset": 849527}
```

`type` is the only value the manager accepts (anything else is `400 invalid_type`; the field exists
for trigger reasons the design anticipates but has not implemented). `feed_offset` resolves exactly
like a VD session's `Start.feed_offset` — one order for both, so a lane cannot end up declaring two
different offsets:

1. the step's own `feed_offset` (a contract scenario pinning a deliberate mismatch);
2. `--vd-feed-offset` (environment config);
3. otherwise the value this agent's keepalive loop learned from `/control`, **waiting** for the
   first notify to report one (30 s cap). The wait matters: the keepalive loop and the lane
   goroutines start together, so without it a `scan_vd` with no `initial_delay` would race the first
   notify and send offset 0.

## Responses

| Outcome | Status | Recorded as | Fails the run? |
|---|---|---|---|
| Queued | `200 {}` | `scan_200` | no |
| `feed_offset` != the node's offset | `409 {"error":"version_mismatch","current_version":N}` | `scan_409` | no |
| Tracking table full (default cap 10000 agents) | `503 {"error":"scan_queue_full"}` | `scan_503` | no |
| Malformed request (`invalid_body`/`invalid_json`/`invalid_type`/`missing_feed_offset`/`invalid_agent_id`) | `400` | `scan_other` | **yes** |
| Credentials (keys not loaded yet, bad MAC) | `401` | `scan_other` | **yes** |

`409` and `503` are ordinary results: they are what a real fleet gets when its offset knowledge went
stale or when a node is saturated, and a scenario may assert them. `400`/`401` mean the sender built
a request the manager cannot even parse — a sender bug, invalid measurement ([10](10-error-handling-and-shutdown.md)).

A `409` carries the node's real offset in `current_version`. The sender **records it and does not
act on it**: a real agent adopts it and retries, but a load generator that reshapes its traffic from
the system under test produces runs that cannot be compared ([03](03-control-protocol.md#what-the-sender-does-with-the-response)).
The one server value that does steer the sender is still notify's `vd_feed_offset`.

## `200` means queued, not scanned

The manager answers at **admission** — offset check plus enqueue — and dispatches the scan afterward
on a worker pool sized to the host's CPUs. Two consequences the report must respect:

- The recorded latency (`scan_latency_ms_*`) is admission time, **not** scan duration. A p99 of 2 ms
  says nothing about how long the scans took.
- Concurrency is an illusion at that layer: `ScanOrchestrator::runScanAfterFeedUpdate()` takes an
  exclusive lock for the whole scan, so the VD module runs **one scan at a time** no matter how many
  workers call it. A 100-agent storm is 100 serialized scans.

Whether the scans ran is therefore **not observable from this side of the wire**. remoted's own
`/scan/vd` counters (`acceptedCount`, `scanSucceededCount`, `scanDiscardedCount`,
`scanRetriesExhaustedCount` in `scanvd/scanVdMetrics.hpp`) live in `remotedModuleFacade` and are not
exposed on any metrics endpoint, so the evidence is modulesd's log:

```text
Vulnerability scan start: agent='005' (5.0.0) type=full reason=feed_update
Vulnerability scan completed: agent='005' type=full reason=feed_update
```

`reason=feed_update` is what distinguishes a `/scan/vd`-triggered scan from the `option=VDFirst` one
a session triggers.

## Scenario shape

`scan_vd` takes only `feed_offset` and the timing fields ([07](07-scenario-schema.md#per-step-timing));
anything describing a payload (`documents`, `dump`, `module`, `option`, `indices`, …) is a load-time
error, because it would mean the author expected the step to send inventory too. Steps within a lane
are sequential, so the real order is expressed by putting it after the inventory step, with
`initial_delay` as the gap that lets the indexing land first:

```json
"vd_linux": [
  { "kind": "delta",   "dump": "../sample_payloads/dumps/vd_first_debian.json" },
  { "kind": "scan_vd", "initial_delay": "90s" }
]
```

A `delta`, not a `full_resync`, on purpose: a `Cleans` session built from a VD dump inherits
`option: VDFirst`, so it is `isVD` and queues in the VD scan lane too — waiting its turn there
**without scanning anything**. At fleet scale that doubles the lane's pressure for no inventory, and
a first connection has nothing to clean. Measured at 100 agents: with the `full_resync` shape the
lane shed thousands of bare `503`s and ~85 VDFirst sessions never landed, after which their re-scans
were *correctly* skipped (`no package inventory available (first scan not completed yet, VDFirst will
cover the updated feed)`) — the storm read as 100 × `200` with a third of the scans running. When a
re-scan storm's numbers look too clean, check `sessions.retries_exhausted` before believing them.

Each request takes one `requests_per_second` token, like a `/stateful` session — which is what makes
a 100-agent re-scan storm shapeable (`0` = all at once, the saturating case).

## Metrics

`scan_sent`, `scan_200`, `scan_409`, `scan_503`, `scan_other` and `scan_latency_ms_p50/p99` in
`bench.csv`; a `scan` block per fleet and per lane in `sender_summary.json`; an `expected.scan.*`
group for the verdict ([09](09-metrics-and-output.md)). `scan_sent` counts requests, and — unlike
`/stateful` sessions — a `scan_vd` step never retries, so attempts and logical requests are the same
number.
