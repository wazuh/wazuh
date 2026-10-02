# 14 — The VD re-scan request (`POST /scan/vd`)

`/scan/vd` is the second, and completely separate, way a scan reaches the Vulnerability Detection
module. Getting the two confused makes a scenario measure something other than what it says, so the
distinction comes first:

| | VDFirst / VDSync `/stateful` session | `POST /scan/vd` |
|---|---|---|
| What it carries | The inventory itself (packages, system, hotfixes) | Nothing but `type` + `feed_offset` (4 KiB body cap) |
| What is scanned | The inventory in **that** session | The inventory the manager **already** holds for that agent |
| Manager-side path | `inventory_sync_server`'s VD scan lane (`src/wazuh_modules/inventory_sync_server/src/vd/vdScanLane.cpp`) | remoted as a synchronous passthrough of VD's admission (`src/remoted/remoted_module/src/scanvd/scanVdHandler.cpp`) → one inline `POST /vulnerability-detector/scan` on `queue/sockets/vd-http.sock`, where VD records a durable `vd_scan` task (`src/wazuh_modules/vulnerability_scanner/src/vulnerabilityScanner.cpp`) → later, the Task Manager's dispatcher runs it through the inventory sync server's `POST /_internal/vd/scan`, on that same VD scan lane |
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
`Authorization: Bearer <wazuh-agent+jwt token>` ([04-wire-protocol.md](04-wire-protocol.md)). The
agent id is the token's verified `sub`; the body
has no identity field. **agent mode only** — the module's Unix socket has no such route, so a `uds`
scenario carrying a `scan_vd` step is refused at load time, exactly like an `engine` step is.

## Request

```json
{"type": "feed_update", "feed_offset": 849527}
```

`feed_update` is the only `type` value the manager accepts (anything else is `400 invalid_type`, a
missing one `400 missing_type`; the field exists for trigger reasons the design anticipates but has
not implemented). `feed_offset` resolves exactly
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
| Recorded (the scan will run) | `200 {}` | `scan_200` | no |
| `feed_offset` != the node's offset | `409 {"error":"version_mismatch","current_version":N}` | `scan_409` | no |
| VD did not record it | `503 {"error":"<cause>"}` — `scan_queue_full` (the bounded number of pending scans is reached) \| `indexer_unavailable` (no healthy indexer host) \| `feed_not_ready` \| `scanner_not_ready` \| `vd_not_initialized` \| `task_create_failed` (the task row could not be written, or the write timed out) \| `vd_unreachable` \| `vd_error` | `scan_503` | no |
| Malformed request (`invalid_body`/`invalid_json`/`missing_type`/`invalid_type`/`missing_feed_offset`/`invalid_agent_id`) | `400` | `scan_other` | **yes** |
| Credentials (keys not loaded yet, bad MAC) | `401` | `scan_other` | **yes** |
| Any other status | — | `scan_other` | no |

`409` and `503` are ordinary results: they are what a real fleet gets when its offset knowledge went
stale or when a node cannot queue the scan right now, and a scenario may assert them. A real agent's
pending state survives a `503` — its next notify re-requests — which is why remoted never retries
on its behalf. `400`/`401` mean the sender built
a request the manager cannot even parse — a sender bug, invalid measurement ([10](10-error-handling-and-shutdown.md)).

A `409` carries the node's real offset in `current_version`. The sender **records it and does not
act on it**: a real agent adopts it and retries, but a load generator that reshapes its traffic from
the system under test produces runs that cannot be compared ([03](03-control-protocol.md#what-the-sender-does-with-the-response)).
The one server value that does steer the sender is still notify's `vd_feed_offset`.

## `200` means recorded, not scanned

remoted is a synchronous passthrough of VD's **admission**: it validates the agent id and the
offset, makes one inline `POST /vulnerability-detector/scan` on the VD module's socket, and relays
the answer (`scanVdHandler.cpp`). VD checks its readiness first (feed loaded, scanner initialized,
at least one healthy indexer host), answering `503` with the cause instead of admitting. Otherwise
it records the scan as a durable `vd_scan` task in the Task Manager and answers `200 {}` at once
(`vulnerabilityScanner.cpp`). That type keeps one pending task per agent (a repeat request
coalesces into it and is still a `200`), at most 64 pending by default (`scan_queue_full` beyond
that), and runs one at a time (`src/wazuh_modules/task_manager/src/registry/builtinTypes.cpp`). The
dispatcher then POSTs each task to the inventory sync server's `/_internal/vd/scan`, which runs it on
the VD scan lane and answers when the scan has run; if the indexer is down at that point, the task
is retried under the Task Manager's retry policy rather than dropped. So a `200 {}` means "VD
recorded the scan and it **will** run". There is no tracking table, no worker pool and no retry in
remoted; any VD refusal or a failed round trip is an honest `503` naming the cause. Two
consequences the report must respect:

- The recorded latency (`scan_latency_ms_*`) is admission time — the offset check, one local UDS
  round trip and VD's task-row write — **not** scan duration. A p99 of a few milliseconds says
  nothing about how long the scans took.
- Concurrency is an illusion at that layer: the `vd_scan` task type runs one task at a time, so a
  100-agent storm is 100 serialized scans.

What became of the scans **is** observable, on two channels. remoted's admin socket exposes the
admission split over `GET /metrics` — `remoted.scanvd.requests.total`, `remoted.scanvd.accepted`,
`remoted.scanvd.queue_full`, `remoted.scanvd.indexer_unavailable`,
`remoted.scanvd.version_mismatch`, `remoted.scanvd.invalid_agent`, `remoted.scanvd.vd_error` (every
other refusal, `task_create_failed` included) — and the scans themselves are in modulesd's log,
tagged `wazuh-manager-modulesd:vulnerability-scanner`:

```text
Vulnerability scan start: agent='005' (5.0.0) type=full reason=feed_update
Vulnerability scan completed: agent='005' type=full reason=feed_update
```

`reason=feed_update` is what distinguishes a `/scan/vd`-triggered scan from the `option=VDFirst` one
a session triggers. The task rows themselves (pending, running, completed, dead-lettered) are the
Task Manager's; see the operator page on
[manager tasks](../../../../docs/ref/modules/task_manager/manager-tasks.md).

## Scenario shape

`scan_vd` takes only `feed_offset` and the timing fields ([07](07-scenario-schema.md#per-step-timing));
anything describing a payload (`documents`, `dump`, `module`, `option`, `indices`, …) is a load-time
error, because it would mean the author expected the step to send inventory too. Steps within a lane
are sequential, so the real order is expressed by putting it after the inventory step, with
`initial_delay` as the gap that lets the indexing land first:

```json
{
  "lanes": {
    "vd_linux": [
      { "kind": "delta",   "dump": "../sample_payloads/dumps/vd_first_debian.json" },
      { "kind": "scan_vd", "initial_delay": "90s" }
    ]
  }
}
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
a 100-agent re-scan storm shapeable (`0` = all at once, the saturating case). The token is taken
after the offset is resolved, so the wait for the first notify is not priced as load.

## Metrics

`scan_sent`, `scan_200`, `scan_409`, `scan_503`, `scan_other` and `scan_latency_ms_p50/p99` in
`bench.csv`; a `scan` block per fleet and per lane in `sender_summary.json`; an `expected.scan.*`
group for the verdict ([09](09-metrics-and-output.md)). `scan_sent` counts requests, and — unlike
`/stateful` sessions — a `scan_vd` step never retries, so attempts and logical requests are the same
number.
