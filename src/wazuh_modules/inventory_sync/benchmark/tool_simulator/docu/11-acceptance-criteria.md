# 11 — Acceptance criteria

This document fixes how parity is demonstrated and the cutover checklist
that must be green before flipping the default `--engine` in
[`run_benchmark.sh`](../../run_benchmark.sh) from `python` to `go`.

## Test plan summary

| ID    | Type       | Scenario                                                       | Pass condition                                                                            |
| ----- | ---------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| AC-A  | Smoke      | `base_init_debian_syscollector.json`                           | Both senders produce a `bench.csv` with `sessions_completed ≥ 1`, `start_ack_ok = 1`, `end_ack_ok ≥ 1`. Counter parity ±0 (single session — must match exactly). |
| AC-B  | Multi-agent| `dump_replay_syscollector_vd_windows_full.json`, 60 s          | Both senders' cumulative `sessions_completed`, `data_values_sent`, `end_ack_ok` agree within ±5 %.                                                                  |
| AC-C  | Saturation | `mega_burst.json`, 2000 agents, 180 s                          | Go sender sustained EPS over the middle 120 s window ≥ 2× Python's, on the same reference host. Memory peak (RSS) ≤ 1.5× Python's. (NFR-7.)                          |
| AC-D  | Wire parity| Single Start, deterministic inputs                             | Hexdump of the first remoted frame from both senders is byte-identical given the same `(name, id, key, flatbuffer_bytes)`. (NFR-2.)                                |
| AC-E  | Manager logs | All scenarios from AC-A..AC-C                                | No `Bad message format` / `Decoding error` / `Invalid checksum` / `inflate error` lines in `/var/wazuh-manager/logs/wazuh-manager.log` from the Go sender's traffic. |
| AC-F  | Output schema | Both senders' `bench.csv` headers                          | Exact byte-equal header lines. (NFR-3.)                                                                                                                              |
| AC-G  | Summary schema | Both senders' `sender_summary.json`                       | `result_summary.py` consumes both without code changes and produces equivalent reports. (NFR-4.)                                                                     |
| AC-H  | Drain      | `base_init_debian_syscollector.json` with manual SIGINT mid-run | First SIGINT → drain completes within `drain_timeout`; exit 0. Second SIGINT within 2 s → exit 130. (FR-13.)                                                          |
| AC-I  | Safeguards | Manager configured with `inventory_sync_data_value_quota=10`, plus a synthetic scenario that exceeds it | Both senders see `start_ack_offline` ≥ 1 and continue with the next iteration / repeat without aborting the agent.                                                  |
| AC-J  | Backwards compat | `--engine=python` on the same `run_benchmark.sh`        | Equivalent run produces a `bench.csv` byte-equal in schema (not values) to Phase 0.                                                                                  |

## Method

### Reference host

All AC-A..AC-C runs MUST be performed on a single, frozen reference host
(record `lscpu`, `free -h`, kernel version). The current CI runner spec is
a reasonable baseline.

### Smoke (AC-A)

```bash
# Python
./run_benchmark.sh --engine=python --scenario scenarios/base_init_debian_syscollector.json
# Go
./run_benchmark.sh --engine=go     --scenario scenarios/base_init_debian_syscollector.json
```

Verify per-row counter values match across `bench.csv`. With a single
session and single agent, every column should be identical second-by-second
(within ±1 row of clock skew).

### Multi-agent (AC-B)

```bash
./run_benchmark.sh --engine=python --scenario scenarios/dump_replay_syscollector_vd_windows_full.json
./run_benchmark.sh --engine=go     --scenario scenarios/dump_replay_syscollector_vd_windows_full.json
```

Compare cumulative totals from `sender_summary.json.messages`. ±5 %
tolerance accounts for non-determinism in EPS pacing and ReqRet timing.

### Saturation (AC-C)

```bash
./run_benchmark.sh --engine=python --scenario scenarios/mega_burst.json
./run_benchmark.sh --engine=go     --scenario scenarios/mega_burst.json
```

Compute sustained EPS over the middle 120 s of the 180 s `repeat_until`
window (skip the first 30 s warmup and last 30 s drain):

```
sustained_eps = sum(data_values_sent[30:150]) / 120
```

Pass: `sustained_eps_go >= 2 * sustained_eps_python`.

Also record `monitor.py`'s wazuh-manager-modulesd RSS — the Go sender
SHOULD not increase manager-side memory pressure (it's the sender that
changed, not the manager).

### Wire parity (AC-D)

Use a controlled fixture:

- `name = "bench-0001-aaaaaaaaaaaa"`
- `id = "001"`
- `manager_key = "deadbeef…"` (32-char hex constant in test fixture)
- One synthetic Start with `module=fim_files`, `mode=ModuleFull`,
  `option=Sync`, `indices=["wazuh-states-fim-files"]`, `size=1`.

Capture the bytes the sender would write (mock the socket; do not actually
send). Compare:

```bash
xxd python_start.bin > /tmp/py.hex
xxd go_start.bin     > /tmp/go.hex
diff /tmp/py.hex /tmp/go.hex      # must be empty
```

If they differ:

- Differ on length prefix → endianness bug.
- Differ on the AES block boundary → wrong padding direction (prepended `!`).
- Differ on the inner-event prefix → routing literals.
- Differ inside FlatBuffer bytes → field ordering / builder bugs (see 06).

### Manager logs (AC-E)

After AC-A/B/C runs:

```bash
sudo grep -E "Bad message format|Decoding error|Invalid checksum|inflate error" \
    /var/wazuh-manager/logs/wazuh-manager.log
```

Must return zero lines attributable to the Go sender's connections (the
agent ids are `bench-…`).

### Schema parity (AC-F, AC-G)

```bash
head -1 bench.csv_python | sha256sum
head -1 bench.csv_go     | sha256sum   # must be equal

python3 result_summary.py --bench bench.csv_go --summary sender_summary_go.json ...
```

If `result_summary.py` crashes or warns about missing columns, AC-F or AC-G
fail.

### Drain (AC-H)

Manual test:

```bash
./run_benchmark.sh --engine=go --scenario scenarios/base_init_debian_syscollector.json &
PID=$!
sleep 5
kill -INT $PID
# wait, expect exit 0 within drain_timeout
wait $PID                # echo $?  → 0
```

Repeat with two `kill -INT` calls within 2 s; expect exit `130`.

### Safeguards (AC-I)

Set in `internal_options.conf`:

```
wazuh_modules.inventory_sync_data_value_quota=10
```

Run a synthetic scenario with `data_size > 10`. The first Start hits the
quota and returns `Status_Offline` (FR-15 in the manager). Verify:

```bash
jq '.messages.start_ack_offline' sender_summary.json   # >= 1
```

And that no agent enters an error state (the runner aborts the session,
the next iteration proceeds).

## Cutover checklist

Tick every item before flipping the default in
[`run_benchmark.sh`](../../run_benchmark.sh).

- [ ] Go binary builds with `CGO_ENABLED=0 go build -trimpath` from `benchmark/tool_simulator/` and is committed under `benchmark/tool_simulator/cmd/benchmark_sender/`.
- [ ] FlatBuffer stubs are committed and regenerated via the existing `flatc` recipe — no checked-in stale output.
- [ ] AC-A passes locally and in CI.
- [ ] AC-B passes locally and in CI.
- [ ] AC-C passes on the reference host. Run logged + EPS numbers committed under `docs/migration/` (or wherever migration artifacts live).
- [ ] AC-D passes — hexdump diff is empty for the fixture in `testdata/`.
- [ ] AC-E passes — clean manager logs after every benchmark.
- [ ] AC-F + AC-G pass — `result_summary.py` runs unchanged.
- [ ] AC-H passes — drain and second-SIGINT semantics correct.
- [ ] AC-I passes — manager safeguards still produce the expected `Status_Offline` and the sender handles them gracefully.
- [ ] `--key-wait 35` default behaves correctly (no `Status_Offline` cascade on fresh manager).
- [ ] `bench.csv` is line-buffered (visible with `tail -F` during the run).
- [ ] Unit tests committed: `wrapFrame`, `DeriveAESKey`, FlatBuffer build/parse, scenario loader rejects malformed inputs, leaky-bucket pacing keeps under cap.
- [ ] `--debug` flag works and produces the same density of logging as Python's debug mode.
- [ ] `run_benchmark.sh`'s shim accepts `--engine=python|go` and `ENGINE=…` env var.
- [ ] `cleanup_agents.sh` still removes Go-launched agents (no behaviour change expected).
- [ ] `monitor.py` graphs render correctly for a Go-driven run.
- [ ] Manager-side `inventorySyncFacade` unit tests still pass (sanity check that contract didn't drift).
- [ ] No new dependencies introduced beyond those listed in [10-go-implementation-notes.md](./10-go-implementation-notes.md).
- [ ] No cgo. Verify with `go build -trimpath -o /dev/null ./...` under `CGO_ENABLED=0` and check the resulting binary with `file`.
- [ ] One-cycle parallel run executed: same `run_benchmark.sh` invocation with both engines, results archived for posterity.
- [ ] Code review by at least one Wazuh engine maintainer.
- [ ] CHANGELOG entry mentioning the engine flip.
- [ ] README / docs in `benchmark/` updated to point at the Go binary as the supported path.

When every box is ticked, flip the default. The Python sender stays in the
repo for one full release cycle as a safety net (`benchmark_sender.py.legacy`),
then is removed.
