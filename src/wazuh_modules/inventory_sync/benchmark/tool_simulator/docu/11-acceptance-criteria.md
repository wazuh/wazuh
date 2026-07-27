# 11 — Acceptance criteria

This document defines how correctness is verified and the checklist that
must be green before a release.

## Test plan summary

| ID    | Type       | Scenario                                                       | Pass condition                                                                            |
| ----- | ---------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| AC-A  | Smoke      | `base_init_debian_syscollector.json`                           | `bench.csv` contains `sessions_completed ≥ 1`, `start_ack_ok = 1`, `end_ack_ok ≥ 1`. With a single session/agent, every per-second counter is stable.                 |
| AC-B  | Multi-agent| `dump_replay_syscollector_vd_windows_full.json`, 60 s          | Cumulative `sessions_completed`, `data_values_sent`, `end_ack_ok` reach expected totals within ±5 % of a known-good baseline.                                           |
| AC-C  | Saturation | `mega_burst.json`, 2000 agents, 180 s                          | Sustained EPS over the middle 120 s window ≥ target threshold documented in the run log. Memory peak (RSS) within bounds (NFR-6).                                        |
| AC-D  | Wire parity| Single Start, deterministic inputs                             | Hexdump of the first remoted frame is byte-identical to the known-good fixture given the same `(name, id, key, flatbuffer_bytes)`. (NFR-2.)                            |
| AC-E  | Manager logs | All scenarios from AC-A..AC-C                                | No `Bad message format` / `Decoding error` / `Invalid checksum` / `inflate error` lines in `/var/wazuh-manager/logs/wazuh-manager.log`.                                |
| AC-F  | Output schema | `bench.csv` header                                         | Header is byte-equal to the expected value recorded in `testdata/bench_header.txt`. (NFR-3.)                                                                          |
| AC-G  | Summary schema | `sender_summary.json`                                     | `result_summary.py` consumes output without code changes and produces a valid report. (NFR-4.)                                                                        |
| AC-H  | Drain      | `base_init_debian_syscollector.json` with manual SIGINT mid-run | First SIGINT → drain completes within `drain_timeout`; exit 0. Second SIGINT within 2 s → exit 130. (FR-13.)                                                          |
| AC-I  | Safeguards | Manager configured with `inventory_sync_data_value_quota=10`, plus a synthetic scenario that exceeds it | `start_ack_offline ≥ 1` in summary and agents continue with the next iteration without aborting.                                                                     |

## Method

### Reference host

All AC-A..AC-C runs MUST be performed on a single, frozen reference host
(record `lscpu`, `free -h`, kernel version). The current CI runner spec is
a reasonable baseline.

### Smoke (AC-A)

```bash
./run_benchmark.sh --scenario scenarios/base_init_debian_syscollector.json
```

Verify per-row counter values are stable second-by-second. With a single
session and single agent every column should be consistent.

### Multi-agent (AC-B)

```bash
./run_benchmark.sh --scenario scenarios/dump_replay_syscollector_vd_windows_full.json
```

Compare cumulative totals from `sender_summary.json.messages` against a
known-good baseline. ±5 %
tolerance accounts for non-determinism in EPS pacing and ReqRet timing.

### Saturation (AC-C)

```bash
./run_benchmark.sh --scenario scenarios/mega_burst.json
```

Compute sustained EPS over the middle 120 s of the 180 s `repeat_until`
window (skip the first 30 s warmup and last 30 s drain):

```
sustained_eps = sum(data_values_sent[30:150]) / 120
```

Record the result in the run log. Compare against the target threshold
noted in the scenario (if set) or the previous run baseline.

Also record `monitor.py`'s wazuh-manager-modulesd RSS — confirm no
unexpected growth compared with prior baseline runs.

### Wire parity (AC-D)

Use a controlled fixture:

- `name = "bench-0001-aaaaaaaaaaaa"` (or `bench-smoke-0001-aaaaaaaaaaaa` for fleet scenarios)
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

### Schema (AC-F, AC-G)

```bash
head -1 bench.csv | sha256sum     # compare against testdata/bench_header.txt checksum

python3 result_summary.py --bench bench.csv --summary sender_summary.json ...
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

## Verification checklist

Tick every item before releasing.

- [ ] Go binary builds with `CGO_ENABLED=0 go build -trimpath` from `benchmark/tool_simulator/`.
- [ ] FlatBuffer stubs are committed and regenerated via the existing `flatc` recipe — no stale output.
- [ ] AC-A passes locally and in CI.
- [ ] AC-B passes locally and in CI.
- [ ] AC-C passes on the reference host. Sustained EPS logged and committed.
- [ ] AC-D passes — hexdump diff is empty for the fixture in `testdata/`.
- [ ] AC-E passes — clean manager logs after every benchmark.
- [ ] AC-F + AC-G pass — `result_summary.py` runs unchanged.
- [ ] AC-H passes — drain and second-SIGINT semantics correct.
- [ ] AC-I passes — manager safeguards still produce the expected `Status_Offline` and the sender handles them gracefully.
- [ ] `--key-wait 35` default behaves correctly (no `Status_Offline` cascade on fresh manager).
- [ ] `bench.csv` is line-buffered (visible with `tail -F` during the run).
- [ ] Unit tests committed: `wrapFrame`, `DeriveAESKey`, FlatBuffer build/parse, scenario loader rejects malformed inputs, leaky-bucket pacing keeps under cap.
- [ ] `--debug` flag works and produces useful verbose output.
- [ ] `cleanup_agents.sh` removes benchmark-launched agents correctly.
- [ ] `monitor.py` graphs render correctly.
- [ ] Manager-side `inventorySyncFacade` unit tests still pass.
- [ ] No new dependencies beyond those listed in [10-go-implementation-notes.md](./10-go-implementation-notes.md).
- [ ] No cgo. Verify with `CGO_ENABLED=0 go build -trimpath -o /dev/null ./...` and check the binary with `file`.
- [ ] Code review by at least one Wazuh engine maintainer.
- [ ] CHANGELOG entry.
