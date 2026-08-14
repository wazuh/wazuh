# 02 — Functional requirements

The HTTP contract of `POST /stateful` as the sender must treat it. The contract itself is defined by
the server (`docs/ref/modules/inventory-sync-server/api-reference.md`) and relayed verbatim by
remoted's `statefulEndpoint`; this document says what the CLIENT does with each answer.

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
| **FR-6** | `400` | Invalid session (shape, empty values, junk body) | Count; **MUST NOT** retry. In a normal scenario a `400` is a **bug in the sender**; only scenarios that deliberately send invalid sessions may expect it |
| **FR-7** | `403` | Identity or cluster mismatch | Count; **MUST NOT** retry. Outside deliberate scenarios this is a sender bug (or a stale `client.keys`) |
| **FR-8** | `409` | `{"status":"checksum_mismatch"}` (a `ModuleCheck` session) or `{"error":"version_mismatch","current_version":N}` (a VDFirst/VDSync session whose `Start.feed_offset` is stale — see [05-flatbuffers-messages.md](05-flatbuffers-messages.md)) | Count both under the same `s409` counter (the two are distinguished by scenario, not by counter — a VD lane's `s409` means version_mismatch, a checksum lane's means checksum_mismatch); a real agent would full-resync (checksum) or re-request with `current_version` (VD). The sender **MUST NOT** do either implicitly — a scenario that wants the resync **MUST** script it as Cleans + Delta, and one that wants to pin the version_mismatch contract **MUST** use a deliberately wrong `feed_offset` (see `contract_vd_version_mismatch.json`) |
| **FR-9** | `413` | The session declares more bytes than the total in-flight budget | Count; **MUST NOT** retry, **MUST NOT** split. This is the measurement in the budget-limit scenario |
| **FR-10** | `500` | Failed with nothing indexed (including a failed vulnerability scan) | Count; **MUST NOT** retry within the run. A non-zero count **SHOULD** be reported prominently: it is the server failing, not backpressure |
| **FR-11** | `503` **with** `Retry-After` | The CVE feed is still downloading (D17) | **MUST** retry after honoring the header, up to `--feed-timeout` (default 300 s); each retry **MUST** be counted as such, not as a fresh session. This is manager bring-up, not load. For a VDFirst/VDSync session the sender **MUST** re-encode `Start.feed_offset` from the current value (step/CLI/learned) before each such retry rather than resending the original bytes — the feed can finish loading, and therefore the server's current offset can change, during a wait this long |
| **FR-12** | `503` **without** `Retry-After` | Indexer unavailable, queue/budget full, scan capacity exhausted, or shutting down | Count; **MUST NOT** retry. This is backpressure — the signal the saturation scenarios exist to find |

## Transport-level answers

| FR | Requirement |
|---|---|
| **FR-13** | `404`, `405`, `411`, `414`, `431`, `504` **MUST** be counted under a single `other` bucket and reported: none of them is reachable by a correct sender, so any occurrence indicates a sender bug or a server regression. |
| **FR-14** | A connection closed without a response, or a read timeout, **MUST** be counted as a transport error distinct from every HTTP status, and **MUST** fail the run when it exceeds a configurable threshold (default: any occurrence in `uds` mode). It was exactly this signal that exposed a real server-side race during F9b, so it **MUST NOT** be silently retried away. |

## Deletion and control

| FR | Requirement |
|---|---|
| **FR-15** | Scenarios **MAY** issue `DELETE /agents` (or its `POST /agents/delete` alias) with `X-Wazuh-Agent-Id`; `200` means the delete-by-query was flushed. UDS-local only — there is no route to it through remoted, so this is a `uds`-mode capability. |
| **FR-16** | In `agent` mode the sender **MUST** send `startup` once per agent before its first session, `notify` at the configured interval, and `shutdown` during drain. See [03-control-protocol.md](03-control-protocol.md). |
| **FR-17** | An engine-stream lane (`agent` mode only) **MUST** ship its events as an H/E batch to `POST /stateless`; success is `202` (not `200`), counted in its own bucket. See [13-engine-event-streams.md](13-engine-event-streams.md). |
| **FR-18** | A `scan_vd` step (`agent` mode only) **MUST** send `POST /scan/vd {"type":"feed_update","feed_offset":N}` with the offset resolved exactly as a VD session's `Start.feed_offset` is. `200` means the re-scan was **queued**, never that it ran, so the sender **MUST NOT** report its latency as a scan duration; `409 version_mismatch` and `503 scan_queue_full` are counted as ordinary outcomes, and the sender **MUST NOT** adopt the `current_version` a `409` returns (a real agent does; a load generator that reshapes itself from the answer stops being comparable). `400` and `401` **MUST** fail the run. See [14-scan-vd.md](14-scan-vd.md). |
