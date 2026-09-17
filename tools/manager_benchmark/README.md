# manager_benchmark

Load generation and reporting for the Wazuh manager's agent-facing ingestion paths. Its first (and
current) target is the **inventory synchronization** path — remoted's `POST /stateful` and the
`inventory_sync_server` behind it — together with the control and engine-event traffic a real fleet
produces alongside it. It lives under `tools/` rather than inside the module because it drives the
manager as a whole (authd enrollment, remoted, the engine ingress), not one module in isolation.

## Status

| Piece | State |
|---|---|
| `tool_simulator/docu/` — design documentation of the sender | **written** (subplan F9c-1) |
| `tool_simulator/` — the Go sender | **built** (subplan F9c-2) |
| `scenarios/` + orchestration scripts | **built** (subplan F9c-3) |
| `LOAD_REPORT.md` — the baseline report | **produced** (subplan F9c-4); generated per environment, not committed |

## Running a benchmark

`run_benchmark.sh` is the entry point: it starts the monitor (process samples plus each daemon's own
statistics), runs the sender against a scenario in either transport mode, then collates everything
into one `summary.json` and plots it.

```bash
# uds mode — straight to the module socket (the ingestion pipeline alone)
./run_benchmark.sh --scenario scenarios/real_syscollector_debian.json --mode uds

# agent mode — enroll the fleet over POST /enroll, then HTTPS to remoted (the whole relay)
sudo ./prepare_manager.sh                                    # one-time: reachable enrollment + the fleet's token
./run_benchmark.sh --scenario scenarios/real_syscollector_debian.json --mode agent
```

**The cluster name is read from the manager's own config.** The server answers `403` to any session
whose `cluster_name` is not its own, and the scenarios only ship a placeholder, so getting this wrong
means 100 % `403` and a run that measures nothing. Rather than make every caller repeat it,
`run_benchmark.sh` reads `<cluster><name>` from
`/var/wazuh-manager/etc/wazuh-manager.conf` — `--conf` points it elsewhere — and prints which value it
used. `--cluster` overrides it. The cluster **node** is not sent at all: sessions declare no
`cluster_node` (the manager never validated it and is dropping its last consumer), so there is no
`--cluster-node` and nothing to detect.

A **remote** `--manager` is deliberately never auto-detected: the local config would then describe a
different manager, and silently declaring the wrong cluster is worse than stopping. In that case pass
`--cluster` explicitly; the effective value is recorded in each run's `params.json`.

If the manager configures a **global endpoint prefix** (`<remote><https><global_prefix>`), agent mode
needs it too — and, exactly like the cluster name, it is read from the local manager's config when
`--global-prefix` is not given, so a default installation needs no flag. A **remote** `--manager` is
not auto-detected for the same reason, and `/` forces the unprefixed paths against a manager that
does have one configured. Getting it wrong is not a soft failure: the prefix is part of the signed
request target, so every request answers `404` and the run looks like a broken manager. A malformed
prefix (an empty segment, a character the manager rejects) is warned about but still sent, so the
tool can reproduce one on purpose. The effective value is recorded in `params.json` and in
`sender_summary.json` under `meta.global_prefix`. The uds transport is never prefixed.

Agent-mode runs also **wait until remoted actually accepts a signed request** before the clock starts,
retrying within `--enroll-settle`. That is not a formality: remoted only knows a freshly enrolled agent
after it reloads `client.keys`, and that took **~100 s** on the reference manager — nothing like the
10 s `remoted.keyupdate_interval` implies. Until then every request is `401`, which has its own counter
and invalidates the run rather than being counted as load. Give big fleets a generous budget
(`--enroll-settle 240s`).

Each run creates `results_<label>/` with `bench.csv` (per-second cumulative counters + latency percentiles), `sender_summary.json` (metadata, totals, the same counters broken down `by_fleet` and `by_lane`, and the scenario's `expected` verdict), `scenario.json` (the exact scenario, copied for reproducibility), `samples/metrics.ndjson` (every daemon's `GET /metrics`, one JSON object per scrape), `summary.json` (what those inputs add up to), `monitor/` (process, disk and log samples) and `charts/`. The sender's formats are pinned by [`docu/09-metrics-and-output.md`](tool_simulator/docu/09-metrics-and-output.md).

### `samples/metrics.ndjson` is the server-side artifact

One file, one JSON object per scrape, every daemon in it (`src` says which). It is **lossless** in a checkable sense: the module's original `/metrics` response can be rebuilt from it, field for field, and the test suite asserts exactly that. Every metric is there under its own name — including the ones no chart is keyed on yet — with its `type`, `unit` and `description`, whether it was enabled, and the daemon's own clock.

Per-metric descriptors (`type`, `unit`, `description`) go on the `meta` line rather than on all 400 scrapes. A manifest is a **revision, not a header**: a module may register a metric after the run has started (the transport diagnostics only exist once the server is up), and the collector re-emits the manifest whenever the descriptors change. A reader folds every manifest of the run, latest wins — `bench_samples.read_descriptors()` / `read_types()` — so a late metric keeps its type instead of arriving with readings and no description of them. `d` carries what the dump said about itself. `off` lists the metrics that reported `enabled: false` in that scrape — `wazuh_metrics` writes a *value* for a disabled metric too (whatever it last held), so without that list a stopped counter reads as a live one flatlining.

```text
{"kind":"run","r":"20260916T181538Z-35d5","started":"...Z","label":"<run label>"}
{"kind":"meta","src":"inventory-sync","socket":"...","r":"...",
 "types":{"sync.docs.indexed":"counter",...},"units":{...},"descriptions":{...}}
{"ts":"...Z","t":12.0,"src":"inventory-sync","ok":true,"m":{"sync.docs.indexed":1234,...},
 "h":{"vd.lane.time":{"count":9,"p50":...,"p99":...},...},
 "d":{"name":"inventory_sync_server","timestamp":"...Z"},"r":"20260916T181538Z-35d5"}
{"ts":"...Z","t":13.0,"src":"inventory-sync","ok":false,"err":"connection refused","r":"..."}
```

**Re-running a label appends to the same file.** `results_<label>/` is reused and the collectors append, so one samples file can hold several runs. Each run opens with a `run` marker and every line carries its `r`; the charts and `summary.json` both read the **last run only**, and `summary.json` records which (`server_metrics.<source>.run`). Reading the file whole instead — `jq` with no filter — spans runs, and a cumulative counter's delta then covers all of them. To scope a query by hand, filter on the last `r`:

```bash
RUN=$(jq -r 'select(.r).r' results_<label>/samples/metrics.ndjson | tail -1)
jq -r --arg r "$RUN" 'select(.r==$r and .src=="inventory-sync" and .ok) | [.t, .m["vd.lane.depth"]] | @tsv' \
    results_<label>/samples/metrics.ndjson
```

Two more rules matter when reading it. A metric the dump did not carry is **absent** from `m`, not zero — "this build does not register it", "this counter has not moved" and "this metric was turned off" are three different facts, and the format keeps all three apart (the third via `off`). A failed scrape carries **no metrics at all**, because zeros would read as a counter reset to anything computing a delta. Histograms live in `h`, so a percentile can never be mistaken for something you may subtract.

Read through `bench_samples.observed()` rather than touching `m` and `h` directly: it returns both with whatever that scrape listed in `off` removed, which is what keeps a disabled metric's stale value — or a disabled histogram's stale distribution — out of a chart or a delta.

Ad-hoc queries need nothing but `jq`:

```bash
# how the VD lane depth moved, as a time series (every run in the file)
jq -r 'select(.src=="inventory-sync" and .ok) | [.t, .m["vd.lane.depth"]] | @tsv' \
    results_<label>/samples/metrics.ndjson

# every metric remoted_module published, whether or not it has a column
jq -r 'select(.src=="remoted-module" and .ok) | .m | keys[]' \
    results_<label>/samples/metrics.ndjson | sort -u
```

**There is no per-daemon CSV any more.** The collectors used to derive one per scrape, next to the samples file; nothing read it (the charts and the summary both prefer the samples file) and it held strictly less — 57 columns against 126 for inventory sync, because a fixed header can only carry what somebody aliased. Ask for one when you want it:

```bash
python3 $WAZUH_DEV_SCRIPTS/bench_samples.py results_<label>              # every daemon
python3 $WAZUH_DEV_SCRIPTS/bench_samples.py results_<label> --src remoted --out-dir /tmp
```

It writes the full projection, so the export has every metric rather than the aliased subset. The format and that projection are defined by `src/engine/tools/devContainer/scripts/bench_samples.py`.

A run recorded before the samples file existed is **not chartable by this build**: the legacy CSV readers went with the CSVs. Re-run the scenario.

The same `samples/metrics.ndjson` file carries the remoted C++ module's statistics under `src: "remoted-module"`, collected from `GET /metrics` over its admin socket (`queue/sockets/remote-admin-http.sock`): the `remoted.control.*` and `remoted.scanvd.*` counters plus the admin server's own transport gauges. The scan-vd family is what a saturation run is read on — an admission split, `scanvd_queue_full` and `scanvd_indexer_unavailable` against `scanvd_accepted` and `scanvd_vd_error`, says how many re-scans VD queued versus refused; the charts render it as `remoted_module_scanvd_funnel_<label>.png` (requests / accepted / queue_full / indexer_unavailable / vd_error / version_mismatch), and it counts the same admissions the sender's `scan_200`/`scan_503` do, so the two sides finally mean the same thing. Remoted's **C** statistics from the legacy framed `getstats` socket are recorded in the same file under `src: "remoted"`; the two sources are disjoint. Both inventory sync and the admin server also report their route-class connection counts and in-flight byte budget, so a shed session can be attributed to the budget or to a class cap rather than guessed at.

**One poller, one format, one source of truth.** The monitor samples the manager's processes *and* polls each daemon's statistics, so it also owns the inventory-sync scrape, and every scrape lands in the same `samples/metrics.ndjson`. `scrape_metrics.sh` stays as a standalone tool, is only started automatically when the monitor cannot run (it needs `psutil`), and now writes that same format — so a missing Python package costs the process samples but never the server's own numbers, and never leaves the collator sniffing which producer had run.

`summary.json` splits each daemon's metrics by **kind**, because what may be computed from a series depends on what it is — and the declared type is in the samples file, so nothing has to be guessed:

| block | which metrics | what it reports |
|---|---|---|
| `counters` | declared `counter` | `first`, `last`, `delta`, `resets` |
| `levels` | declared `gauge_int` / `pull` | `first`, `last`, `min`, `max` — **no delta** |
| `text` | non-numeric readings | the value |
| `histograms` | declared `histogram` | the last distribution |

The server's counters are **cumulative for the module's lifetime**, not per run, so `delta` is what belongs to a given run. It is the sum of the rises, not `last - first`: a daemon that restarts mid-run makes its counters fall, and the work done after the restart still counts — `resets` says it happened rather than the run reporting a negative number.

A level gets no delta at all. Five live sessions then two is not "-3 sessions"; it is a level that moved, and `min`/`max` are what describe it. Percentiles are likewise absent from any delta, which the samples file makes structural by keeping histograms in their own object.

`delta`, `final` and `peak` remain as flat name-to-number views for tooling that indexes by metric name; `delta` holds **counters only**, which is the one place the word means something.

`summary.json` carries what it computed and **names** its other inputs rather than copying them (`inputs` lists them, relative to the run directory). It used to embed `params.json` verbatim and six of `sender_summary.json`'s seven keys byte-identically while dropping the seventh — `expected`, the scenario's verdict, the only judgment in the set. The verdict is now in `summary.json` (condensed: `passed`, `checked`, `failed`, `first_failure`), with the full failure list still in `sender_summary.json`. `processes` covers every process the monitor sampled, not modulesd alone.

### The sender on its own

`run_benchmark.sh` wraps the Go binary; you can also drive it directly:

```bash
cd tool_simulator
make all                       # flatc --go bindings + go build -> ./benchmark_sender
make test                      # wazuh-agent+jwt frozen vector + FlatBuffers round-trip

./benchmark_sender --scenario ../scenarios/<scenario>.json --validate      # load + strict-check only
./benchmark_sender --scenario ../scenarios/<scenario>.json --mode uds \
                   --socket /var/wazuh-manager/queue/sockets/inventory-sync-http.sock
```

The FlatBuffers Go bindings are generated by `make`, never committed. The design is documented before
the code on purpose: the sender reproduces the manager's authentication and wire contracts byte for
byte, and those are worth pinning down in prose (and cross-checking against the manager's sources)
before they are implemented.

## Scenarios

A scenario is one JSON file describing a run in the lanes-and-fleets model
([`docu/07-scenario-schema.md`](tool_simulator/docu/07-scenario-schema.md)). The library lives in
[`scenarios/`](scenarios/) and its layout — what each file exercises, and how it maps to a manager
code path — is documented in [`SCENARIOS.md`](SCENARIOS.md). `--validate` strict-checks a file
(unknown field, unknown step kind, or a missing referenced payload is a hard error) without sending
anything; the whole library is kept green that way.

Most scenarios generate documents deterministically from a seed, but the `real_*` ones replay **real
captured payloads** from [`sample_payloads/dumps/`](sample_payloads/dumps/) so the wire bytes match
production shapes — see the real-payloads section of `SCENARIOS.md`. The `real_first_connect*` pair
replays a Windows and a Linux agent's first connection at FULL fidelity (the Windows FIM registry
corpus is 27,726 documents in one ~26 MB session), which in agent mode requires the sender's
**zstd request compression** — the agent-mode default, like a real 5.x agent (`defaults.compression`
in the scenario or `--compression zstd|none` per run; remoted decompresses, the UDS socket takes
only plain bodies, so uds runs are always plain).

A VDFirst/VDSync session's `Start.feed_offset` MUST match the manager's current VD feed offset or
it is rejected with `409 version_mismatch` before ever reaching the scanner. `--mode agent` learns
the offset live from remoted's `/control` (the same signal a real agent uses); `--mode uds` has no
`/control` to learn it from, so pass `--vd-feed-offset <value>` explicitly — query the live value
with `curl --unix-socket queue/sockets/vd-http.sock http://localhost/vulnerability-detector/offset` —
against a target whose feed offset is not 0, or every VD scenario's sessions fast-reject with `409`
instead of exercising a real scan. See `SCENARIOS.md` for which scenarios this affects.

The same offset gates the **other** way a scan reaches the VD module: `POST /scan/vd`, the
feed-update re-scan a real agent asks for once `/control` reports a higher `vd_feed_offset`. A
scenario sends one with a `scan_vd` step (agent mode only), typically right after the VD inventory
step and with an `initial_delay` so the documents it re-scans have landed first —
`scenarios/real_vd_rescan_storm.json` does exactly that with 100 agents. It is a different manager
path from a VDFirst session's scan (remoted relaying VD's admission instead of the inventory
pipeline's VD scan lane), and its `200` means **queued by VD**, not scanned: the scans themselves
show up in the manager's log as `reason=feed_update`. Full contract in
[`docu/14-scan-vd.md`](tool_simulator/docu/14-scan-vd.md).

## Manager preparation (agent mode)

Agent-mode runs enroll a synthetic fleet the way a 5.x agent handed an enrollment token does — `POST
/enroll` on 1517 with a `wazuh-enroll+jwt` bearer — so the manager under test keeps the **enrollment
policy it was installed with**. `prepare_manager.sh` does three things; the first two soften
nothing, and the third removes a rate ceiling deliberately:

1. makes remote enrollment reachable: `<auth>` gets `disabled=no`, `remote_enrollment=yes`
   (optionally `max_agents=N`) — remoted serves `/enroll` only while both hold;
2. mints **one multi-use enrollment token** for the fleet (`wazuh-manager-authd
   --create-enrollment-token`, authd's defaults: 30 days, unlimited uses) and writes it to
   `.enrollment_token` next to the script, which `run_benchmark.sh` picks up by itself;
3. sets `<remote><https>`'s `enroll_rate_limit` and `cacerts_rate_limit` to `0` — the documented
   "no limit" (issue #39129). Those two routes ship with a rate limit (100 and 50 req/s), counted
   **for the endpoint as a whole rather than per agent**, so a harness asking faster than a fleet's
   steady state — which is the whole point of a capacity run — gets `429`s from a perfectly healthy
   manager: the `cacerts` scenario's 200 unpaced requests would spend the burst and see roughly half
   refused. `--keep-rate-limits` leaves the shipped values in place, which is how you benchmark the
   limiter itself; the sender counts a `429` as an ordinary outcome either way (`cacerts_429`,
   `enroll_https_429`, assertable as `s429`).

`<use_password>` and `etc/authd.pass` are left exactly as installed. That is the point of issue
#39054: benchmarking used to require `use_password=no`, a configuration no production manager has,
and a config flip the script had to apply and undo.

The mint is validated against the running listener certificate, so its `--address` must be one of
that certificate's SANs; the default is read from the certificate itself. `--address` overrides it,
and `--no-mint` skips minting (bring your own token with `--enroll-token-file`). It is idempotent and
writes a one-time `.bak`.

### Bootstrapping over the legacy 1515 listener

`--bootstrap 1515` enrolls the fleet through authd's plaintext-inside-TLS listener instead, which is
kept for comparing the two first-contact paths. That protocol carries no credential, so it needs the
old flip — which is now explicit:

```bash
sudo ./prepare_manager.sh --open-1515      # ALSO sets use_password=no and removes etc/authd.pass
./run_benchmark.sh --scenario scenarios/real_syscollector_debian.json --mode agent --bootstrap 1515
```

It opens unauthenticated enrollment to anything that can reach port 1515, which is why it is not the
default any more — and a later `prepare_manager.sh` **without** the flag does not undo it: put
`<use_password>` back by hand (the one-time `.bak` has the original) when done comparing. Each run
records which bootstrap it used in `sender_summary.json` (`meta.bootstrap`) and `params.json`, so two
runs are never confused for one another.

## Inspecting a run's indexed data (agent mode)

By default an agent-mode run's `bench-*` agents are **not** deleted afterward — but the *next*
agent-mode run (or the next `run_matrix.sh` entry) deletes them first, to avoid an enrollment name
clash, and deleting an agent purges its documents from the indexer too. So a single run's data
already survives; a second run wipes it. To inspect the real dumps' data in the indexer's dashboard
across several runs, pass `--keep-agents` to `run_benchmark.sh` or `run_matrix.sh`:

```bash
./run_benchmark.sh --scenario scenarios/real_first_connect.json --mode agent --keep-agents
# ... inspect wazuh-states-* in the indexer's dashboard, filtering by the bench-* agent(s) ...
./cleanup_agents.sh   # delete the bench-* agents (and their indexed documents) when done
```

`--keep-agents` is mutually exclusive with `--cleanup-after`. In `run_matrix.sh` it applies to every
agent-mode entry in the matrix; since the matrix's own scenarios use non-overlapping `first_id`
ranges, one full pass (or a `--only` subset) does not collide with itself — re-running the whole
matrix a *second* time without cleaning up first will (enrollment fails with "Duplicate agent
name"). Not needed in `uds` mode: those runs never enroll a real agent, so nothing ever deletes
their indexed documents.

**`scenarios/real_inspect_fleet.json`** is purpose-built for this: one Windows agent and one Linux
agent, each replaying every real inventory module (FIM, syscollector, SCA, VD) at full fidelity, plus
a basic engine lane whose own `repeat_count` keeps both agents connected and keepaliving for several
extra minutes after the inventory sessions land — time to actually get to the dashboard before the
run exits. Pair it with `--keep-agents` so the documents survive after that too:

```bash
./run_benchmark.sh --scenario scenarios/real_inspect_fleet.json --mode agent --keep-agents
```

## Helper scripts

| Script | What it does |
|---|---|
| `run_benchmark.sh` | Orchestrates one run end to end (monitor + sender + summary + charts) |
| `prepare_manager.sh` | Makes remote enrollment reachable, mints the fleet's enrollment token and clears the two unauthenticated routes' rate limits (idempotent); `--open-1515` for the legacy bootstrap, `--keep-rate-limits` to benchmark the limiter |
| `scrape_metrics.sh` | Wrapper around `bench_collect.py`, the collector the monitor also runs — same loop, same validation, same lines. Only started automatically when the monitor cannot run (it needs psutil) |
| `cleanup_agents.sh` | Deletes only `bench-*` agents via the Wazuh API (never a real one) |
| `indexer_control.sh` | Start/stop/health the local `wazuh-indexer` (e.g. an indexer-down scenario) |
| `result_summary.py` | Collates a run's artifacts into `summary.json` — every daemon's metric deltas, every process's resource aggregates, the scenario's verdict (descriptive only, no pass/fail) |
| `run_matrix.sh` | Runs the whole matrix the load report is built from |
| `make_report_tables.py` | Turns the resulting `results_*/` into the report's tables |

## Regenerating the load report

`LOAD_REPORT.md` is **not committed**: its numbers belong to the machine that produced them, so a
report from someone else's laptop would be misleading as a reference. The matrix that produces it is
committed instead, so any environment can regenerate the whole thing:

```bash
sudo ./prepare_manager.sh              # reachable enrollment + the fleet's token (agent mode)
./run_matrix.sh                        # 12 runs -> results_<label>/
./make_report_tables.py > tables.md    # environment + status + latency + throughput tables
```

Nothing else is required against a local manager: the cluster name comes from its config. For a
remote one, add `--cluster <its cluster name>`.

`run_matrix.sh` pins the seed (4242) and the labels, so two environments produce comparable runs.
Optionally describe the host in `bench_env.txt` (one `key: value` per line — `cpu`, `cores`,
`mem_total`, `kernel`, `indexer`, `git_head`) and `make_report_tables.py` puts it in the environment
table; anything missing is skipped rather than guessed.

A run that exits `1` or `2` is **not** a slow manager — it means the measurement itself is invalid
(an unauthenticated fleet, a transport error, a setup failure). Fix it before quoting numbers. Exit
`3` is different: the measurement is valid, but the scenario's optional `expected` block (counter
assertions — see `tool_simulator/docu/07-scenario-schema.md`) failed; `sender_summary.json` names
each failed assertion with its actual value.

## What it will measure

The same scenarios over two transports, so the difference isolates the relay:

- **`--mode uds`** — straight to the module's Unix socket (`POST /stateful`), measuring the
  ingestion pipeline alone: validation, sharded workers, group commit, the vulnerability-detection
  scan lane.
- **`--mode agent`** — like a real fleet: enroll over `POST /enroll` with an enrollment token
  (`--bootstrap 1515` for the legacy listener), then HTTPS to remoted with a
  `wazuh-agent+jwt` bearer token per request, sending `POST /control` (`startup`, a `notify` keepalive every 10 s, `shutdown`) and
  the `POST /stateful` sessions. A `cacerts` step adds the unauthenticated `GET /cacerts` (the CA that
  signs the listener certificate) — the trust bootstrap a real agent does first, and the floor of the
  listener's fixed per-request cost since nothing sits downstream of it (`scenarios/cacerts.json`).
  An `enroll_https` step MEASURES that same first-contact path under load
  (`scenarios/enroll_https.json`): each repetition enrolls a fresh `bench-…-tk-N` agent, on top of
  the one enrollment per agent the bootstrap already did, and its cost is reported in its own
  `enroll_https_*` counters — the fleet's own bootstrap is setup and is never folded into them. Both
  use the token from `--enroll-token-file` / `WAZUH_ENROLLMENT_TOKEN` / `.enrollment_token`, and
  `cleanup_agents.sh` removes every `bench-*` agent either produced.

Per run it produces `bench.csv` (per-second cumulative counters and latency percentiles),
`sender_summary.json` (metadata, totals, per-kind histograms — plus the `expected` verdict when the
scenario opts into one) and a scrape of the
server's own `GET /metrics`, so client-observed behavior can be correlated with shard depths, bulk
flushes and scan-lane timings.

## Start here

[`tool_simulator/docu/00-index.md`](tool_simulator/docu/00-index.md) — index, glossary and reading
order. The two documents worth reading first are `01-overview.md` (what this measures and what it
deliberately does not do) and `03-control-protocol.md` (the `POST /control` contract, which was not
documented for a synthetic client until now).

## Related

- System under test: [`docs/ref/modules/inventory-sync-server/`](../../docs/ref/modules/inventory-sync-server/README.md)
- The module's developer map (requirements, design decisions D1–D22, developer FAQ):
  [`inventory_sync_server/README.md`](../../src/wazuh_modules/inventory_sync_server/README.md)
- Correctness (not performance): the integration QA in [`inventory_sync_server/qa/`](../../src/wazuh_modules/inventory_sync_server/qa/README.md)
- Runtime statistics the monitor scrapes: `GET /metrics`, documented in the API reference
