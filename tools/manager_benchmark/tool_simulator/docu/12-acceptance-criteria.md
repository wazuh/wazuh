# 12 — Acceptance criteria

What F9c-2 must demonstrate for the sender to be considered done. Each criterion is checkable by a
person with a devcontainer, and F9c-2's subplan closes against this list.

| AC | Criterion | How it is shown |
|---|---|---|
| **AC-A** | Builds and vets clean, no cgo | `go build ./...` and `go vet ./...` succeed; `file` on the binary shows a static-ish Go executable |
| **AC-B** | Signature parity with remoted | The CMAC vector self-test passes, and a signed request against the REAL manager returns something other than `401` for every route used (`/control`, `/stateful`) |
| **AC-C** | Enrollment works against a password-less authd | A run with `fleet.agents: 3` enrolls 3 agents and records their ids in `meta.agents_enrolled`; the ids appear in the manager's `client.keys` |
| **AC-D** | Control traffic is real and its answers are discarded | A 60 s run with `keepalive_interval: 5s` and 3 agents shows ~36 `control_notify_ok`; the code contains no read of `limits`, `agent.groups`, `config_hash`, `settings_hash` or `tasks` beyond validation (reviewable by grep) |
| **AC-E** | `uds` mode drives the server alone | A run against the QA harness (`inventory_sync_server_testtool --serve --no-vd`) produces `sessions_ok > 0` and documents visible in the indexer |
| **AC-F** | Both modes run the same scenario | One scenario file, two modes, two artifact sets whose `meta.mode` differ and whose session counts match |
| **AC-G** | The contract paths are reachable on purpose | Dedicated scenarios produce, each in its own run: a `413`, a `503` without `Retry-After`, a `409`, and a `400` from a `raw` step — each counted in its own column, and NONE of them sets a non-zero exit code (they are results, not failures) |
| **AC-M** | Heterogeneous fleets run in parallel | The mixed-fleet scenario (two fleets, each several inventory lanes plus an engine lane) runs; `by_fleet` and `by_lane` in the summary show the per-fleet and per-lane breakdown, and the engine lane's `stateless_202`/`events_sent` are non-zero and isolated from the session counters |
| **AC-N** | Records everything, judges nothing | The summary contains no verdict/pass/expected-ratio field; a run with a deliberate flood of `503`s still exits `0`; every status and every latency is present per-lane and per-fleet |
| **AC-H** | Feed retry works | With a manager whose CVE feed is still downloading, a VD scenario shows `sessions_503_retry_after` and `retries_feed` > 0 and eventually `sessions_ok` > 0, without exceeding `--feed-timeout` |
| **AC-I** | Artifacts match [09](09-metrics-and-output.md) exactly | Header of `bench.csv` compared field by field with the document; `sender_summary.json` validated against the documented shape (a JSON-schema check is **RECOMMENDED**) |
| **AC-J** | Drain is clean and bounded | SIGINT mid-run drains within `--drain-timeout`, sends `shutdown` per agent, writes complete artifacts, and reports `abandoned_on_drain` honestly; a second SIGINT exits at once |
| **AC-K** | Failures are loud | A deliberately wrong key produces an immediate abort naming the signing input, not a run full of `401`s; a deliberately deep working directory produces the `AF_UNIX` path error up front |
| **AC-L** | Reproducibility | Two runs of the same scenario with the same seed send byte-identical payloads (verifiable by hashing the generated documents) and record identical `meta` except timestamps |

## Out of scope for these criteria

Absolute performance numbers are **not** an acceptance criterion of the tool: they are the deliverable
of F9c-4, and any target here would prejudge the baseline the report is supposed to establish. The
tool is done when it measures faithfully and fails loudly — not when it reaches a particular
throughput.
