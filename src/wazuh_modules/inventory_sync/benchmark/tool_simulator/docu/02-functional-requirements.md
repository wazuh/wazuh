# 02 — Functional requirements

This document enumerates the required behaviours of the Go sender. Each
FR has a short statement and a verification handle (the column in
`bench.csv`, the test scenario that exercises it, or the manager log line
to grep for).

## Section 0 — Manager contract

The sender is a client of `wazuh-remoted` + `wazuh-authd`. The semantics of
each `Status_*` value returned in `StartAck`/`EndAck` come from
[`inventorySyncFacade.hpp`](../../../src/inventorySyncFacade.hpp) and must be
interpreted as follows:

| Code                          | When the manager sends it                                                                                   | Sender reaction                                                                                                |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `Status_Ok (0)`               | Happy path — session created or completed cleanly                                                          | Increment `start_ack_ok` / `end_ack_ok`; latency recorded                                                       |
| `Status_Error (1)`            | Hard reject. Examples: agent locked by another `Mode_Metadata*`/`Mode_Group*` session, invalid Start fields | Increment `start_ack_error` / `end_ack_error`; pre-StartAck → abort the runner; post-StartAck → count and exit |
| `Status_Offline (2)`          | Backpressure. Examples: `inventory_sync_data_value_quota` exhausted (default 500000), `m_maxSessions` reached, indexer unreachable | Increment `start_ack_offline` / `end_ack_offline`; do **not** retry inside the runner — the scenario decides |
| `Status_ChecksumMismatch (3)` | Only for `Mode_ModuleCheck` — agent's checksum does not match manager's                                    | If step has `auto_resync=true`, queue a follow-up delta session immediately                                     |
| `Status_Processing (4)`       | Intermediate ack from `handleEnd` — the indexer-queue handler is still working                              | Record latency for "end_ack_processing"; keep waiting for the final ack                                         |

Two safeguards configurable via `internal_options.conf` (`wazuh_modules`
section) directly affect the sender under stress:

- `inventory_sync_queue_size` (default `10000`) — caps the input router
  queue. Inbound router messages are dropped when full and the manager logs
  a rate-limited warning every 90 s. The sender does **not** observe drops
  directly; it only sees missing acks. The acceptance suite includes a
  saturation test that watches `messages_dropped` in `bench.csv`.
- `inventory_sync_data_value_quota` (default `500000`) — global cap on the
  cumulative `Start.size` of active sessions. When exhausted, new Starts
  return `Status_Offline` with `session=UINT64_MAX`. The fixture
  `data_value_quota_exhausted_flow.json` in the integration tests verifies
  this path; the Go sender's behaviour MUST match.

## Functional requirements

| ID    | Statement                                                                                                                                                            | Verification                                                                       |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| FR-1  | Parse the scenario JSON, validate (`lanes` non-empty, XOR between `total_agents` and `fleets`, `repeat_until>=0`), normalise (merge `defaults` into each step, resolve relative `dump` paths). | Reject bad scenarios with a clear stderr message and exit non-zero before opening any socket. |
| FR-2  | Enrol each agent against `wazuh-authd` (`tcp/1515`) with a unique name derived from the fleet and index: `bench-<fleet>-<NNNN>-<rand12>` when the scenario uses `fleets`, or `bench-<NNNN>-<rand12>` for the single-fleet `total_agents` shorthand. Derive the AES key from the response. | Manager API shows `bench-*` agents; `agents_registered` in `sender_summary.json.meta`. |
| FR-3  | Connect each agent to `wazuh-remoted` (`tcp/1514`); send the `#!-agent startup` control message.                                                                       | TCP capture shows the control frame; `socket_alive=true` before the lane loop.     |
| FR-4  | For each `(agent, lane, step)` triple, run the session state machine matching `session_type` (`delta`, `modulecheck`, `dataclean`). Lanes within the same agent run **in parallel**; steps within a lane run **sequentially**. | Total sessions started = `Σ(fleet_agents × Σ(repeat_count) per lane)` per pass.     |
| FR-5  | Source payloads from a `dump` file (replay) or generate from a `kind` template + optional `payload_size` padding. Preserve per-item `index` for dumps (multi-index). | Compare `_index` of generated docs against scenario manifest for replay tests.     |
| FR-6  | Enforce per-session `max_eps` with a leaky bucket: target time per message is `t0 + sent/cap`; sleep if ahead.                                                         | EPS in `bench.csv` ≤ cap over a 10-second moving average.                          |
| FR-7  | Honour step-level `repeat_count`, `initial_delay`, `repeat_delay`; honour scenario-level `repeat_until` (loop entire lanes for N seconds, 0 = single pass).             | Stop wall-clock matches `start + repeat_until` ± 1 s.                              |
| FR-8  | Honour `parallel_agents`: `0` ⇒ all agents start together at a barrier; `>0` ⇒ sliding window cap via semaphore. After an agent finishes its iteration, another may enter. | Manual: log "wave N start/finish" matches the cap.                                 |
| FR-9  | Handle `ReqRet` when `retransmit=true`: resend missing seqs from the in-memory item list (dump mode) or re-synthesise (kind mode). Cap at 5 retransmit rounds per session; on exhaustion count `messages_dropped` and fail the session. | `reqret`, `missing_ranges_total`, `messages_dropped` columns in `bench.csv`.       |
| FR-10 | Record per-second counters (`COUNTER_FIELDS` listed in [08-metrics-and-output.md](./08-metrics-and-output.md)) to `bench.csv`; record latency percentiles for `start_ack`, `end_ack`, `session_full` to `sender_summary.json`. | Schema in 08 file; `result_summary.py` consumes both unchanged.                    |
| FR-11 | Stream `bench.csv` row-by-row (no batched-end-of-run flush) so the in-flight monitor and a human watcher see progress in real time.                                    | `tail -F bench.csv` updates every ~1 s during the run.                             |
| FR-12 | Drain at end of run: stop creating new sessions, keep the reader alive, count "in-flight" sessions; exit when in-flight reaches 0 OR `drain_timeout` elapses.           | The "drain" log lines in stdout show in-flight monotonically decreasing.           |
| FR-13 | On the first `SIGINT` / `SIGTERM`, flip a shared "running" flag to false and enter drain. On a second signal within the same lifetime, exit with `130` immediately. | Manual: two Ctrl+C in a row reproduce the behaviour.                               |
| FR-14 | Pre-`StartAck` failure (timeout, socket dead, refused) aborts the runner; the agent moves to the next step or lane. Post-`StartAck` failures are counted but do **not** retry inside the runner. | `sessions_failed` column; logs distinguish pre-vs-post failures.                   |
| FR-15 | Between iterations of the same agent (when `repeat_until>0`), tear down the connection, sleep 1 s, reconnect. If reconnect fails, count all remaining sessions of that agent as failed and exit the agent loop. | `sessions_failed` jumps by the number of remaining sessions for that agent.        |
| FR-16 | Honour the agent / module / option mapping in the dump's metadata block: `module` (string), `mode` (`ModuleFull` etc.), `option` (`Sync`/`VDFirst`/`VDSync`), `indices` (list).  | Replay fidelity: the manager logs the same module name and mode it saw originally. |
| FR-17 | `--key-wait` (default 35 s) — after enrolment completes, sleep this long before connecting to remoted, so the manager has time to reload its keys table.            | When running against a fresh manager: no `Status_Offline` cascade during the first wave. |
| FR-18 | When `use_databatch=true`, group items into `DataBatch` messages whose serialised size stays below a 60 KB target. Single-item batches are allowed; an empty batch is never sent. | Manual: `wireshark` filter on remoted shows `DataBatch` content_type instead of `DataValue`. |
| FR-19 | When `payload_size>0` is set on a `kind` step, expand the field identified by `pad_field` (or the per-kind default) with arbitrary bytes until `len(json_marshal(template)) ≈ payload_size`. | Send a known kind with `payload_size=8192`; inspect `data` length on the wire.     |
| FR-20 | Tag-based `StartAck` dispatch: the manager echoes the module identifier (e.g. `syscollector_sync`) in every inbound `StartAck` wire prefix (`#!-<tag> <fb>`). The reader MUST match each `StartAck` to the **first live pending runner whose tag equals that identifier**. Within the same tag, FIFO order is preserved. Dead (timed-out / cancelled) entries are skipped and pruned. | `TestDispatch_MatchesStartAckByTag` in `internal/agent/fifo_test.go`; if broken, concurrent `fim_sync` + `syscollector_sync` Starts will silently swap session ids and subsequent DataValues will be rejected by the manager. |

## Non-functional requirements

| ID     | Statement                                                                                                                                                                       |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| NFR-1  | The sender exposes the CLI flags documented in [10-go-implementation-notes.md](./10-go-implementation-notes.md). No required flags beyond `--scenario`.                        |
| NFR-2  | The wire output (registration message and every remoted frame) MUST be byte-identical given the same inputs (`name`, `id`, `key`, scenario payload). Verified by the deterministic fixture in AC-D. |
| NFR-3  | The `bench.csv` schema (header row + field types) MUST be unchanged so [`result_summary.py`](../../result_summary.py) keeps working without modification.                          |
| NFR-4  | The `sender_summary.json` schema MUST be unchanged so the charts pipeline keeps working.                                                                                        |
| NFR-5  | The binary MUST NOT depend on cgo for crypto/zlib so it cross-compiles cleanly.                                                                                                 |
| NFR-6  | Memory footprint per simulated agent MUST be ≤ ~2 MB at steady state to leave headroom on the CI runner under 2000-agent scenarios.                                             |
| NFR-7  | The sustained EPS achievable under `mega_burst.json` on the reference hardware SHOULD be ≥2× the previously logged baseline.                                                       |

## Out of scope

- Generating new scenarios or new `sample_payloads/`.
- Implementing agent registration over UDP, mTLS, or anything other than the
  existing TCP+TLS+`OSSEC A:` flow.
- Talking to wazuh-indexer directly. The sender only talks to wazuh-authd
  and wazuh-remoted.
- New telemetry / new CSV columns. The point is parity, not feature creep.
