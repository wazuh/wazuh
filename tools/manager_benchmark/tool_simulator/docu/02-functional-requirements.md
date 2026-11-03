# 02 — Functional requirements

The HTTP contract of `POST /stateful` as the sender must treat it. The contract itself is defined by
the server ([`api-reference.md`](../../../../docs/ref/modules/inventory-sync-server/api-reference.md#the-stateful-session-semantics))
and relayed verbatim by remoted's `statefulEndpoint`; this document says what the CLIENT does with
each answer.

Each requirement states what the implemented sender does (`internal/runner/session.go`,
`internal/metrics/metrics.go`); none is aspirational.

## The session contract

| FR | Requirement |
|---|---|
| **FR-1** | One session **MUST** be one request: one `Message{FullSession}` body, one response. The sender **MUST NOT** implement acknowledgments, sequence numbers, gap recovery or any multi-message session. |
| **FR-2** | The sender **MUST** send `X-Wazuh-Agent-Id` on every `/stateful` request (in `uds` mode it sets the header itself; in `agent` mode remoted sets it from the authenticated identity, so the sender **MUST NOT** send it and **MUST** put the same identity in `Start.agentid`). |
| **FR-3** | `Start.cluster_name` **MUST** match the manager's configured cluster, or every session is answered `403`. The value **MUST** come from the run configuration, never be guessed. |
| **FR-4** | The response body **MUST** be recorded but **MUST NOT** drive control flow beyond the status code and `Retry-After`. |

## Status codes the sender must handle

| FR | Status | Meaning | Sender behavior |
|---|---|---|---|
| **FR-5** | `200` | Applied AND flushed (and scanned, for VD sessions) | Count as success; record latency. `{"status":"ok","noop":true}` **MUST** be counted separately from `{"status":"ok"}` — a run whose sessions were all filtered measured nothing |
| **FR-6** | `400` | Invalid session (shape, empty values, junk body) | Count in `sessions_400`; **MUST NOT** retry, and the run goes on. In a normal scenario a `400` is a **bug in the sender** (or a missing cluster name); only an `expected` block turns it into a failed run |
| **FR-7** | `403` | Identity or cluster mismatch | Count in `sessions_403`; **MUST NOT** retry, and the run goes on. Outside deliberate scenarios this is a wrong `--cluster` or a sender bug |
| **FR-8** | `409` | `{"status":"checksum_mismatch"}` (a `ModuleCheck` session) or `{"error":"version_mismatch","current_version":N}` (a VDFirst/VDSync session whose `Start.feed_offset` is stale — see [05-flatbuffers-messages.md](05-flatbuffers-messages.md)) | Count both under the same `s409` counter (the two are distinguished by scenario, not by counter — a VD lane's `s409` means version_mismatch, a checksum lane's means checksum_mismatch); a real agent would full-resync (checksum) or re-request with `current_version` (VD). The sender **MUST NOT** do either implicitly — a scenario that wants the resync **MUST** script it as Cleans + Delta, and one that wants to pin the version_mismatch contract **MUST** use a deliberately wrong `feed_offset` (see `contract_vd_version_mismatch.json`) |
| **FR-9** | `413` | The session declares more bytes than the total in-flight budget | Count; **MUST NOT** retry, **MUST NOT** split. This is the measurement in the budget-limit scenario |
| **FR-10** | `500` | Failed with nothing indexed (including a failed vulnerability scan) | Count; **MUST NOT** retry within the run. A non-zero count **SHOULD** be reported prominently: it is the server failing, not backpressure |
| **FR-11** | `503` **with** `Retry-After` | The CVE feed is still downloading (D17) | **MUST** retry after honoring the header (read as whole seconds, clamped to 1–30 s), until `--feed-timeout` (default 300 s, counted from the session's first attempt) has passed; each re-send is counted in `retries_feed`, a spent budget in `retries_exhausted`. This path ignores `defaults.retry.enabled`, but its attempts count toward `max_attempts` if the session later meets a bare `503`. This is manager bring-up, not load. For a VDFirst/VDSync session the sender **MUST** re-encode `Start.feed_offset` from the current value (step/CLI/learned) before each such retry rather than resending the original bytes — the feed can finish loading, and therefore the server's current offset can change, during a wait this long |
| **FR-12** | `503` **without** `Retry-After` | Indexer unavailable, queue/budget full, scan capacity exhausted, or shutting down | Backpressure — the signal the saturation scenarios exist to find. The sender re-sends the same buffer, as a real agent does, per `defaults.retry` (on by default, 500 ms apart, 10 sends in all); each re-send is counted in `retries_503` and a spent budget in `retries_exhausted`. A scenario that sets `retry.enabled: false` counts the `503` and moves on (see [07](07-scenario-schema.md#retry-defaultsretry)) |

## Transport-level answers

| FR | Requirement |
|---|---|
| **FR-13** | Every status outside `200`, `400`, `401`, `403`, `409`, `413`, `500` and `503` (a `404` from a prefix mismatch, `405`, `411`, `414`, `415`, `431`, `502`, `504`, …) **MUST** be counted under the single `sessions_other` bucket and reported: none of them is reachable by a correct sender, so any occurrence indicates a sender bug or a server regression. A `401` is not one of them: it has its own counter (`sessions_401`) and invalidates the run (exit `1`), because it means remoted has not loaded the fleet's keys. |
| **FR-14** | A connection closed without a response, or a timeout, **MUST** be counted in `transport_errors`, distinct from every HTTP status, and **MUST NOT** be retried (the step moves on). It was exactly this signal that exposed a real server-side race during F9b. In `uds` mode any transport error fails the run (exit `1`); in `agent` mode it does not, and a scenario that cares asserts `transport_errors` in its `expected` block. |

## Deletion and control

| FR | Requirement |
|---|---|
| **FR-15** | Scenarios **MAY** issue `POST /_internal/agents/delete` (`kind: "delete_agent"`) with body `{"agent_id":"<id>"}` and no `X-Wazuh-Agent-Id` — that is what the Task Manager's dispatcher sends; `200` means the delete-by-query ran and flushed and is counted in `deletes_ok`, any other status in `deletes_err`. Manager-internal and UDS-local — there is no route to it through remoted, so the loader refuses the step outside `uds` mode. |
| **FR-16** | In `agent` mode, when the scenario enables control traffic (`defaults.control.enabled`), the sender **MUST** send `startup` once per agent before its first session, `notify` at the configured interval, and `shutdown` once that agent's lanes finish (at the latest, during drain). See [03-control-protocol.md](03-control-protocol.md). |
| **FR-17** | An engine-stream lane (`agent` mode only) **MUST** ship its events as an H/E batch to `POST /stateless`; success is `202` (not `200`), counted in its own bucket, and a `400` invalidates the run. See [13-engine-event-streams.md](13-engine-event-streams.md). |
| **FR-18** | A `scan_vd` step (`agent` mode only) **MUST** send `POST /scan/vd {"type":"feed_update","feed_offset":N}` with the offset resolved exactly as a VD session's `Start.feed_offset` is. `200` means the re-scan was **recorded as a durable `vd_scan` task** (it will run), never that it ran yet, so the sender **MUST NOT** report its latency as a scan duration; `409 version_mismatch` and `503` (whose body names the cause, `scan_queue_full` among others) are counted as ordinary outcomes, and the sender **MUST NOT** adopt the `current_version` a `409` returns (a real agent does; a load generator that reshapes itself from the answer stops being comparable). `400`, `401` and a `200` whose body is not JSON **MUST** fail the run. See [14-scan-vd.md](14-scan-vd.md). |
