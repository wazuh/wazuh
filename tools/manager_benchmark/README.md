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

# uds mode with engine lanes — straight to the engine's POST /events/enriched (no remoted, no enrollment)
./run_benchmark.sh --scenario scenarios/engine_direct_flood.json --mode uds \
                   --socket /var/wazuh-manager/queue/sockets/engine-ingest-http.sock
```

**The cluster name is read from the manager's own config.** The server answers `403` to any session
whose `cluster_name` is not its own, and the scenarios only ship a placeholder, so getting this wrong
means 100 % `403` and a run that measures nothing. Rather than make every caller repeat it,
`run_benchmark.sh` reads `<cluster><name>` from
`/etc/wazuh-manager/wazuh-manager.conf` — `--conf` points it elsewhere — and prints which value it
used. `--cluster` overrides it. There is no cluster **node** to send: the `Start` table of
`inventorySync.fbs` has no `cluster_node` field any more, so there is no `--cluster-node` and
nothing to detect.

A **remote** `--manager` is deliberately never auto-detected: the local config would then describe a
different manager, and silently declaring the wrong cluster is worse than stopping. In that case pass
`--cluster` explicitly; the effective value is recorded in each run's `params.json`.

Every HTTPS route of the manager lives under a **global endpoint prefix**
(`<remote><https><global_prefix>`, default `/wazuh-manager/`), and agent mode must send it too.
Exactly like the cluster name, it is read from the local manager's config when `--global-prefix` is
not given. The installer always writes the tag, so a default installation needs no flag. One case is
not covered: the script reads only the tag. If an operator deletes `<global_prefix>`, the manager
falls back to the schema default `/wazuh-manager/` while the script finds nothing and sends bare
paths, so pass `--global-prefix /wazuh-manager/` in that case. A **remote** `--manager` is not
auto-detected, for the same reason as the cluster name, and `/` forces the unprefixed paths. Getting
it wrong is not a soft failure: the prefix is part of the route, so every request answers `404` and
the run looks like a broken manager. The prefix is not signed, because the bearer token binds only
the agent's identity, so a prefix mismatch is never a `401`. A malformed prefix (an empty segment, a
character the manager rejects) is warned about but still sent, so the tool can reproduce one on
purpose. The effective value is recorded in `params.json` and in `sender_summary.json` under
`meta.global_prefix`. The uds transport is never prefixed.

Agent-mode runs also **wait until remoted actually accepts a signed request** before the clock starts.
The sender probes with one `POST /control` `startup` every 2 s, and the budget is `--enroll-settle`
with a 30 s floor (the 12 s default therefore waits up to 30 s). That is not a formality: remoted
only knows a freshly enrolled agent after it reloads `client.keys`, and that took **~100 s** on the
reference manager, far longer than the 10 s `remoted.keyupdate_interval` implies. Until then every
request is `401`, which has its own counter and invalidates the run rather than being counted as
load. Give big fleets a generous budget (`--enroll-settle 240s`, which is what `run_matrix.sh`
passes).

Each run creates `results_<label>/` with `bench.csv` (per-second cumulative counters + latency percentiles), `sender_summary.json` (metadata, totals, the same counters broken down `by_fleet` and `by_lane`, and the scenario's `expected` verdict), `scenario.json` (the exact scenario, copied for reproducibility), `samples/metrics.ndjson` (every daemon's `GET /metrics`, one JSON object per scrape), `summary.json` (what those inputs add up to), `monitor/` (process, disk and log samples) and `charts/`. The sender's formats are pinned by [`docu/09-metrics-and-output.md`](tool_simulator/docu/09-metrics-and-output.md).

### `samples/metrics.ndjson` is the server-side artifact

One file, one JSON object per scrape, every daemon in it (`src` says which). It is **lossless** in a checkable sense: the module's original `/metrics` response can be rebuilt from it, field for field, and the test suite asserts exactly that. Every metric is there under its own name — including the ones no chart is keyed on yet — with its `type`, `unit` and `description`, whether it was enabled, and the daemon's own clock.

Per-metric descriptors (`type`, `unit`, `description`) go on the `meta` line rather than on every scrape. A manifest is a **revision, not a header**: a module may register a metric after the run has started (the transport diagnostics only exist once the server is up), and the collector re-emits the manifest whenever the descriptors change. A reader folds every manifest of the run, latest wins — `bench_samples.read_descriptors()` / `read_types()` — so a late metric keeps its type instead of arriving with readings and no description of them. `d` carries what the dump said about itself. `off` lists the metrics that reported `enabled: false` in that scrape — `wazuh_metrics` writes a *value* for a disabled metric too (whatever it last held), so without that list a stopped counter reads as a live one flatlining.

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

**Per-daemon CSV export is optional.** The collectors used to derive one per scrape, next to the samples file; nothing read it (the charts and the summary both prefer the samples file) and it held strictly less, because a fixed header can only carry what somebody aliased. Add `--export-csv` to export every daemon with samples after collection ends:

```bash
./run_benchmark.sh --scenario scenarios/real_syscollector_debian.json --mode uds --export-csv
```

Exports go to `results_<label>/stats-api-*.csv` and include only the latest run when a label is reused. This option requires `pandas` and works with `--no-charts`. If samples are unavailable, export is skipped; missing dependencies or export failures are reported without changing the sender's exit code. CSV export is disabled by default.

You can also export an existing run separately:

```bash
python3 ../devContainer/scripts/bench_samples.py results_<label>              # every daemon
python3 ../devContainer/scripts/bench_samples.py results_<label> --src remoted --out-dir /tmp
```

(Inside the devcontainer, `$WAZUH_DEV_SCRIPTS` points at the same directory.) It writes the full projection, so the export has every metric rather than the aliased subset. The format and that projection are defined by `tools/devContainer/scripts/bench_samples.py`.

A run recorded before the samples file existed is **not chartable by this build**: the legacy CSV readers went with the CSVs. Re-run the scenario.

The same `samples/metrics.ndjson` file carries the remoted C++ module's statistics under `src: "remoted-module"`, collected from `GET /metrics` over its admin socket (`queue/sockets/remote-admin-http.sock`): every `remoted.*` family the module registers (`control`, `scanvd`, `auth`, `enroll`, `cacerts`, `download`, `forwarder`, `server`, `admin`, `http`), the admin server's own transport gauges among them; the catalog is [remoted's metrics page](../../docs/ref/modules/remoted/metrics.md). The scan-vd family is what a saturation run is read on — an admission split, `scanvd_queue_full` and `scanvd_indexer_unavailable` against `scanvd_accepted` and `scanvd_vd_error`, says how many re-scans VD queued versus refused; the charts render it as `remoted_module_scanvd_funnel_<label>.png` (requests / accepted / queue_full / indexer_unavailable / vd_error / version_mismatch), and it counts the same admissions the sender's `scan_200`/`scan_503` do, so the two sides finally mean the same thing. Remoted's **C** statistics from the legacy framed `getstats` socket are recorded in the same file under `src: "remoted"`; the two sources are disjoint. Both inventory sync and the admin server also report their route-class connection counts and in-flight byte budget, so a shed session can be attributed to the budget or to a class cap rather than guessed at.

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
make test                      # go test ./... (JWT frozen vectors, FlatBuffers round-trip, ...)

./benchmark_sender --scenario ../scenarios/<scenario>.json --validate      # load + strict-check only
./benchmark_sender --scenario ../scenarios/<scenario>.json --mode uds \
                   --socket /var/wazuh-manager/queue/sockets/inventory-sync-http.sock
```

No CI lane builds the sender or runs its Go tests; run `make test` yourself after changing it.
The Python side (`result_summary.py`, under `tests/`) runs in
[5_testunit_dev-tools.yml](../../.github/workflows/5_testunit_dev-tools.yml):
`python -m pytest -rs tests` from this directory, with `pytest psutil pandas matplotlib` installed;
the job fails on any skipped case.

The FlatBuffers Go bindings are generated by `make`, never committed. `make generate` runs the
`flatc` at the Makefile's default `FLATC` path (`src/external/flatbuffers/build/flatc`, in the
dependency tree); set `FLATC=` to use another one. `run_benchmark.sh` rebuilds a stale binary with `make build` only, so run `make all`
once on a fresh checkout. The design is documented before
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
instead of exercising a real scan. `run_benchmark.sh` has no `--vd-feed-offset` option of its own,
so for a uds VD run call the sender directly (see [The sender on its own](#the-sender-on-its-own)).
See `SCENARIOS.md` for which scenarios this affects.

The same offset gates the **other** way a scan reaches the VD module: `POST /scan/vd`, the
feed-update re-scan a real agent asks for once `/control` reports a higher `vd_feed_offset`. A
scenario sends one with a `scan_vd` step (agent mode only), typically right after the VD inventory
step and with an `initial_delay` so the documents it re-scans have landed first —
`scenarios/real_vd_rescan_storm.json` does exactly that with 100 agents. It is a different manager
path from a VDFirst session's scan: remoted relays the VD module's admission, which records a
durable `vd_scan` task in the Task Manager, and the Task Manager's dispatcher later runs it through
the inventory sync server. Its `200` means **recorded and will run**, not scanned: the scans
themselves show up in the manager's log as `reason=on_demand`. Full contract in
[`docu/14-scan-vd.md`](tool_simulator/docu/14-scan-vd.md).

## Manager preparation (agent mode)

Agent-mode runs enroll a synthetic fleet the way a 5.x agent handed an enrollment token does — `POST
/enroll` on 1517 with a `wazuh-enroll+jwt` bearer — so the manager under test keeps the **enrollment
policy it was installed with**. `prepare_manager.sh` does three things; the first two soften
nothing, and the third removes a rate ceiling deliberately:

1. makes remote enrollment reachable: `<auth>` gets `disabled=no`, `remote_enrollment=yes`. The
   `/enroll` route is always registered, but it answers `403` unless both hold. `--max-agents N`
   also sets the enrollment cap, which is not a configuration-file option: the script writes the
   internal option `authd.max_agents=N` (an integer in `[0, 2147483647]`, `0` = no limit, the
   default) to `/etc/wazuh-manager/wazuh-manager-internal-options.conf` (`--internal-options PATH`
   names another file), replacing an earlier value, and removes a stale `<auth><max_agents>` element an earlier version of the script wrote
   (the schema refuses it, so it would keep the manager from starting);
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

`<use_password>` and `/etc/wazuh-manager/authd.pass` are left exactly as installed. That is the point of issue
#39054: benchmarking used to require `use_password=no`, a configuration no production manager has,
and a config flip the script had to apply and undo.

The mint is validated against the running listener certificate, so its `--address` must be one of
that certificate's SANs; the default is read from the certificate itself. `--address` overrides it,
and `--no-mint` skips minting (bring your own token with `--enroll-token-file`). It is idempotent and
writes a one-time `.bak`.

### Bootstrapping over the legacy 1515 listener

`--bootstrap 1515` enrolls the fleet through authd's plaintext-inside-TLS listener instead, which is
kept for comparing the two first-contact paths. The listener must be up: `<auth><legacy_enrollment>`
follows `<remote><legacy><enabled>` when it is not set, and the installer enables the legacy
block. That protocol carries no credential, so it needs the old flip, which is now explicit:

```bash
sudo ./prepare_manager.sh --open-1515      # ALSO sets use_password=no and removes /etc/wazuh-manager/authd.pass
./run_benchmark.sh --scenario scenarios/real_syscollector_debian.json --mode agent --bootstrap 1515
```

It opens unauthenticated enrollment to anything that can reach port 1515, which is why it is not the
default any more — and a later `prepare_manager.sh` **without** the flag does not undo it: put
`<use_password>` back by hand (the one-time `.bak` has the original) when done comparing. Each run
records which bootstrap it used in `sender_summary.json` (`meta.bootstrap`) and `params.json`, so two
runs are never confused for one another.

### The Server API password

`cleanup_agents.sh` (which `run_benchmark.sh` and `run_matrix.sh` call before every agent-mode
run) authenticates as `WAZUH_API_USER` (default `wazuh`). Its password has no default, because a
5.x installation generates the `wazuh` user's password and publishes it as
`WAZUH_MANAGER_API_PASSWORD` in `/etc/wazuh-manager/export/credentials.env` (root-only; see
[Credentials](../../docs/ref/getting-started/credentials.md)). The script takes the first of
`WAZUH_API_PASS`, `WAZUH_MANAGER_API_PASSWORD`, and that file's line when the caller can read it
(under `sudo`). For an unprivileged run, export it once:

```bash
export WAZUH_API_PASS="$(sudo sed -n 's/^WAZUH_MANAGER_API_PASSWORD=//p' /etc/wazuh-manager/export/credentials.env)"
```

Without a password, with one the API refuses (`401`), or with the API down, the script prints why
and exits 1; `run_benchmark.sh` and `run_matrix.sh` then print a `WARNING: pre-run cleanup FAILED`
on stderr and run anyway. The previous run's `bench-*` agents then stay, so re-enrolling the same
names fails with "Duplicate agent name" (authd's `<auth><force>` policy refuses to replace an agent
registered less than `after_registration_time`, 1 h by default, ago).

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
| `prepare_manager.sh` | Makes remote enrollment reachable, mints the fleet's enrollment token and clears the two unauthenticated routes' rate limits (idempotent); `--open-1515` for the legacy bootstrap, `--keep-rate-limits` to benchmark the limiter; `--save-side` / `--side` snapshot and restore a build for the A/B |
| `scrape_metrics.sh` | Wrapper around `bench_collect.py`, the collector the monitor also runs — same loop, same validation, same lines. Only started automatically when the monitor cannot run (it needs psutil) |
| `cleanup_agents.sh` | Deletes only `bench-*` agents via the Server API (never a real one); `--all` deletes every agent. Credentials come from `WAZUH_API_URL`, `WAZUH_API_USER` and `WAZUH_API_PASS` (or the published `WAZUH_MANAGER_API_PASSWORD`, see below); exits 1 when it cannot authenticate; exits 1 if the DELETE fails or any agent it targeted survives |
| `indexer_control.sh` | Start/stop/health the local `wazuh-indexer`, by hand (no script calls it), e.g. to stop it during a run and observe the manager with the indexer down |
| `result_summary.py` | Collates a run's artifacts into `summary.json` — every daemon's metric deltas, every process's resource aggregates, the scenario's verdict (descriptive only, no pass/fail) |
| `run_matrix.sh` | Runs the whole matrix the load report is built from |
| `ab_indexer.sh` | The indexer A/B (v1 against v2) in ABBA order, drain and fixed-rate scenarios; `--dry-run` prints the plan and touches nothing |
| `indexer_ingest_probe.sh` | Samples `_count` and `_stats/indexing` per index pattern every second, from the indexer's side |
| `ab_report.py` | `collect` (one run's `ab_metrics.json`) and `report` (medians, spread, v2/v1 ratio, verdict) |
| `make_report_tables.py` | Turns the resulting `results_*/` into the report's tables |

## A/B of the manager's indexer sender

The manager's engine, inventory sync server and vulnerability scanner write to the indexer through
one sender. The A/B asks whether the new one (**v2**, `indexer_client`) sends at least as well as the
one it replaced (**v1**, `indexer_connector`): requirement RNF-3. It is wired here and run by hand,
with the manager free (nothing else may build or measure while it runs).

**Sides.** Each build is installed once (Release; v1 is the merge-base of the branch's final HEAD,
re-fixed whenever the branch is rebased) and saved as a snapshot with
`sudo ./prepare_manager.sh --save-side v1|v2`: a tar of `bin/`, `lib/` and the framework's
`site-packages`, its file list, and the internal-options file as installed. `--side v1|v2` restores
one **whole**: it stops the manager, deletes what the other side added, unpacks the tar, applies the
side's internal-options (the snapshot's file plus `ab_options/<side>.conf`, which gives both sides the
same queue capacity, so the comparison is of senders and not of queue sizes), runs
`wazuh-manager-conf validate` and restarts. A partial swap crashes at startup, so there is no partial
mode. The shared `/etc/wazuh-manager/wazuh-manager.conf` is not touched; prepare it once with
`sudo ./prepare_manager.sh` for agent-mode scenarios.

**Scenarios** (`./ab_indexer.sh --list`):

| Name | Kind | Measures |
|---|---|---|
| `drain-engine` | drain | The indexer is paused (`docker pause`) for the whole run and resumed after it; the manager's backlog drains. Documents/s during the drain and seconds until the count stops growing, **from the indexer's `_count`** (`scenarios/ab_drain_engine.json`) |
| `drain-syscollector` | drain | The indexer is paused while 32 agents' sessions are in flight, then resumed after `--pause-seconds`; sessions/s over the run (`scenarios/ab_drain_syscollector_debian.json`) |
| `fixed-engine`, `fixed-syscollector`, `fixed-fim`, `fixed-vd` | fixed | The existing fixed-rate scenarios (`engine_fleet_load`, `syscollector_init_debian`, `fim_first_sync_ubuntu`, `vd_first_then_sync_debian`): latency, CPU and RSS as a no-regression check. Reported, **no verdict**: at a fixed offered load both sides sustain it and the ratio is 1 by construction |

**Sizing the drain backlog.** `drain-engine` must not overflow either queue, or each side drains
what *its* accounting kept and the run is `INCOMPARABLE`; and it must last several seconds, or the 1 s
probe cannot measure it. Both sides get `analysisd.indexer_queue_max_bytes` = 1 GiB (`ab_options/*.conf`,
1,073,741,824 B; v2 also raises `indexer_client_global_quota_bytes` to 2 GiB so the engine's `events`
and `raw` buckets fit). v2 charges every event `payload + RESULT_RESERVE_BYTES` (2,048,
`src/shared_modules/indexer_client/src/write/bucket.hpp`); v1 charges the bulk payload only, so it fits
whenever v2 does. The scenario sends 25 agents x 1,000 syslog lines x 4 passes = **100,000 events**.
Keeping the backlog at half the quota (536,870,912 B) leaves room for `payload + 2,048 <= 5,368`, a
payload of up to 3,320 B (an enriched syslog event is about 1 to 2 KiB). At an assumed 3 KiB payload:
v2 100,000 x 5,120 = 512 MB (47.7 %), v1 100,000 x 3,072 = 307 MB. The queue size is a cap, not an
allocation: the fixed-rate scenarios never approach it. Check it on the first smoke: every `drain.json`
must say `"engine_events_dropped": 0` (the report is `INCOMPARABLE` otherwise); if not, lower the fleet.
Raising `agents` or `repeat_count` means redoing this sum. Not every event becomes a document: with the
store's ruleset the syslog sample classifies half of its lines (the rest are `events.unclassified` and
are not indexed), and remoted may answer part of the 10 k events/s burst `503`, which the sender does not
retry. Both are the same on the two sides, so the A/B compares fractions, not totals (below).

A paused indexer is `docker pause wazuh-indexer`, not `indexer_control.sh stop`: that script uses
`service`, which does not exist inside the e2e container.

**Order and runs.** `--n` runs per side (default 4, even), in ABBA order (`ABBA BAAB`), after one
warm-up run per side that is discarded. Every run restores its side first, so each starts with the
same empty queues. Labels are `ab-<side>-<scenario>-<i>` (`w` for the warm-up), results in
`results_<label>/` with `provenance.txt` (sha256 of `bin/wazuh-manager-analysisd`,
`bin/wazuh-manager-modulesd` and `lib/*.so`, and whether the config validates), `probe.csv`,
`drain.json` and `ab_metrics.json`. Before every agent-mode run `cleanup_agents.sh` removes the `bench-*`
agents; if it fails (no API password, a refused login, agents still registered after the DELETE) the
run is aborted, since its enrollment would answer `409`. Between runs the indexer is emptied by an **allow-list**
(`wazuh-events*`, `wazuh-states-*`, and `AB_RAW_PATTERN` when set, the same on both sides); the
dot-indices (`.wazuh-threatintel-*`, `.wazuh-cti-consumers`) are never touched, because the
vulnerability scenario needs the feed. The measurement holds an exclusive `flock -o` on
`AB_MEASURE_LOCK` for the whole window: only the `flock` process holds it, and its descriptor is closed
before the campaign runs, so the manager daemons that a restore restarts (and that outlive the campaign)
never inherit it.

**End of a run.** A run ends when the indexer's summed `_count` has not grown for `--quiet-seconds`
(default **and floor** 60: after a resume the sender idles for a node health probe, its backoff and the
async flush, so a shorter quiet would end the run before the drain starts), or at `--drain-timeout`
(600 s, the hard cap: that run is not a valid measurement). There is no "expected total" end: the
documents a run will index are not known ahead (unclassified events, remoted's `503`). `drain.json`
records which one ended it (`drain_end`: `quiet` or `timeout`), the final count (`docs_final`), what the
manager **accepted** from the sender (`events_sent`, `events_accepted`, `events_rejected_503`, from
`sender_summary.json`: the events of the batches answered anything but `202` never reach the engine;
`ab_report.py accepted`) and the engine's `indexer.events.dropped` read from its API
(`AB_ENGINE_API_SOCKET`, `POST /metrics/dump`) at the end of the run (`engine_events_dropped`, `null`
when the API did not answer; every run restarts the manager, so it is that run's count).

**Verdict (I204).** The main metric is documents (`_count` per pattern, the same set of patterns on
both sides); `index_total` (operations) is kept as a diagnostic, because the two builds may issue a
different number of operations per document. Per verdict metric, `ab_report.py` takes the median of
each side and the ratio v2/v1 (a time is inverted, so above 1.00 always favours v2):

| Ratio | Verdict |
|---|---|
| >= 1.00 | `PASS` |
| 0.95 to 1.00 | `PASS_WITHIN_NOISE` |
| < 0.95 | `FAIL` |

It applies **only** to documents/s and time to drain of `drain-engine` and sessions/s of
`drain-syscollector`; everything else is reported with its spread. Guards keep it honest (I226):

- **Same indexed fraction.** For a document drain (`drain-engine`) both sides must index the same
  fraction of the events the manager accepted: `indexed_fraction = docs_drained / events_accepted`,
  medians within 1 % (relative). A side that loses documents indexes a smaller fraction; the absolute
  counts may differ (one side got more `503`s), and then the report adds a note that `drain_seconds`
  favours the side with fewer documents while `docs_per_s_drain` does not.
- **Nothing dropped.** In every measured run of a drain scenario, on both sides, the engine's
  `indexer.events.dropped` must be 0 and known; otherwise the scenario is `INCOMPARABLE` with the run
  and the count in its notes. (For `drain-syscollector` this is the engine's counter only.)
- **Same documents, for a sessions drain.** `drain-syscollector` (verdict sessions/s) has no fraction
  (the sessions' `documents_sent` counts every attempt), but there the sender retries every `503`, so
  both sides are offered the same documents: the medians of `docs_drained` must be within 1 %. A side
  that keeps fewer sessions during the pause (they are abandoned once the sender's retry budget,
  `max_attempts` 10 x 500 ms, runs out: `sessions_abandoned`) indexes fewer documents, and its
  sessions/s measures how fast it rejected, not how fast it sent.

`INCOMPARABLE` names its reason in the report's notes, and a `Comparability:` line gives both sides'
fractions and drop counts. And every run records the sha256 of its provenance snapshot: a side whose runs come from more than
one set of binaries (another HEAD, another snapshot) is `INCOMPLETE`. A side whose repetitions differ by
more than 10 % of their median gets a note to repeat with `N >= 5`. The exit status of
`./ab_indexer.sh --report` is 0 for a pass, 1 for a fail and 2 for incomplete or incomparable data.

**Campaigns.** Every real `ab_indexer.sh` invocation stamps a campaign id (UTC time + random) on the runs
it collects, and the report it prints at the end reads **only** those runs, so the results of an earlier
campaign (longer, shorter, or aborted) never reach the medians. A run deletes the previous
`ab_metrics.json` and `drain.json` of its directory before it starts. If any scenario aborted, the exit
status is never 0 (at least 2). `./ab_indexer.sh --report` has no campaign: it reads every
`results_ab-*`, so clear stale ones first. A missing results directory is reported and exits 2.
A drain run whose `docker pause` fails is aborted (not a valid measurement). `drain-syscollector`
counts only `wazuh-states-inventory-*`, so VD's `wazuh-states-vulnerabilities-*` documents do not end the
wait early.

```bash
./ab_indexer.sh --dry-run                            # the whole plan, touching nothing
sudo ./prepare_manager.sh --save-side v1             # once per side, from that build's install
sudo ./ab_indexer.sh --scenario drain-engine --n 2   # smoke: 1 scenario, 2 runs per side
sudo ./ab_indexer.sh                                 # everything, N = 4 per side
./ab_indexer.sh --report                             # results_ab/ab_report.{json,md}
```

The real run needs `sudo`: every run restores a side, which stops the manager and rewrites its
`bin/`, `lib/` and `/etc/wazuh-manager/wazuh-manager-internal-options.conf`.

**Going back.** The A/B leaves the manager on the last side it ran, with that side's internal-options.
The first restore saves the original file once as `wazuh-manager-internal-options.conf.ab-orig`.
`sudo ./prepare_manager.sh --restore-original` puts it back and restarts the manager; the binaries are
not covered by it, so first `sudo ./prepare_manager.sh --side vX --side-only` with the saved side that
matches your original install (or reinstall with the `stack-env` fresh install).

The indexer credentials have **no default** (no `admin:admin`; `indexer_credentials.sh`, shared by
`indexer_ingest_probe.sh`, `ab_indexer.sh` and `indexer_control.sh`): `INDEXER_USER` + `INDEXER_PASSWORD`,
else the `WAZUH_INDEXER_ADMIN_PASSWORD` line (user `admin`) parsed, never sourced, from
`INDEXER_CREDENTIALS_FILE`, else from the e2e stack's `tools/devContainer/e2e/.credentials.env` of this
checkout or the indexer's `/etc/wazuh-indexer/export/credentials.env` (root-only). Without one a real
campaign exits 1 before taking the lock (a dry run needs none). The certificate is verified with
`INDEXER_CACERT`, else the `<indexer><ssl><certificate_authorities><ca>` of the manager's config, else
`/etc/wazuh-manager/certs/indexer-ca.pem`; `-k` only with `INDEXER_INSECURE=1`. A stack whose
`.credentials.env` lives in another worktree: `export INDEXER_CREDENTIALS_FILE=<that worktree>/tools/devContainer/e2e/.credentials.env`.
Nothing is stored or printed. Without `INDEXER_URL` the address is
the first `<indexer><hosts><host>` of `/etc/wazuh-manager/wazuh-manager.conf` (`WAZUH_MANAGER_CONF`), the
one the manager writes to, else `https://127.0.0.1:9200` (never `localhost`: the e2e node's certificate
names `IP:127.0.0.1` and `DNS:wazuh-indexer` only).

Every restore waits, before the run, for the manager log to say
`inventory-sync-server: INFO: The indexer is reachable` after the restart and for the
`inventory-sync-http.sock` and engine API sockets (cap 150 s, else the run aborts); the agent cleanup
is retried 6 x 10 s, because authd applies the DELETE asynchronously right after a restart. The probe
takes one complete sample (`_count` and `_stats`) before the pause and the sender: `index_total` is
cumulative since the node started, so `index_total_delta` needs that baseline, and without it the
metric is left out instead of reading 0. `monitor.py` attaches only to processes of its own mount
namespace (never a pod's or the indexer container's daemon with the same path) and, for the manager
daemons, to the PID of `/var/wazuh-manager/var/run/<daemon>-<pid>.pid`: with the e2e indexer in a
container, `cpu_pct_avg`/`rss_mb_max` cover the manager's daemons only. The agent cleaner takes `WAZUH_API_USER` /
`WAZUH_API_PASS`; without a password it reads the resolver's `/etc/wazuh-manager/export/credentials.env`
(root only, parsed, never sourced); there is no default password. Tests:
`python3 -m pytest tests/test_ab_report.py`.

## Regenerating the load report

`LOAD_REPORT.md` is **not committed**: its numbers belong to the machine that produced them, so a
report from someone else's laptop would be misleading as a reference. The matrix that produces it is
committed instead, so any environment can regenerate the whole thing:

```bash
sudo ./prepare_manager.sh              # reachable enrollment + the fleet's token (agent mode)
./run_matrix.sh                        # 14 runs -> results_<label>/
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
  `wazuh-agent+jwt` bearer token per request, sending `POST /control` (`startup`, a `notify` keepalive every `defaults.control.keepalive_interval`, 10 s when unset, `shutdown`) and
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
- The module's developer map (requirements, design decisions D1–D31, developer FAQ):
  [`inventory_sync_server/README.md`](../../src/wazuh_modules/inventory_sync_server/README.md)
- Correctness (not performance): the integration QA in [`inventory_sync_server/qa/`](../../src/wazuh_modules/inventory_sync_server/qa/README.md)
- Runtime statistics the monitor scrapes: `GET /metrics`, documented in the inventory sync server's
  [API reference](../../docs/ref/modules/inventory-sync-server/api-reference.md#get-metrics) and in
  [remoted's metric catalog](../../docs/ref/modules/remoted/metrics.md)
