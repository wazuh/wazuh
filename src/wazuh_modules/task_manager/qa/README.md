# Task Manager integration suite

Drives the real module through `task_manager_testtool`: the actual shared object, the actual socket,
the actual database. These tests exist to cover what the gtest suite structurally cannot — the wire,
real concurrency across worker threads, and recovery after the process is killed with rows still
claimed.

## Running

```bash
# The testtool is built unconditionally with the module (no UNIT_TEST needed) and lands in
# src/build/bin/. After a configured build, the target alone is enough:
cmake --build src/build --target task_manager_testtool -j$(nproc)

pip install -r src/wazuh_modules/task_manager/qa/requirements.txt
cd src/wazuh_modules/task_manager/qa
WAZUH_BUILD=../../../build python -m pytest -vv --log-cli-level=INFO
```

This is what [5_testintegration_taskmanager.yml](../../../../.github/workflows/5_testintegration_taskmanager.yml)
runs. The testtool is looked up at `$WAZUH_BUILD/bin/task_manager_testtool` (`WAZUH_BUILD` defaults to
`build`, relative to the working directory); `--testtool /path/to/task_manager_testtool` overrides the
lookup. When the binary is absent every test is **skipped** and pytest still exits 0, so a green run
proves nothing until the summary shows tests passed.

## What is here

| File | Covers |
| --- | --- |
| `test_agent_tasks.py` | Creation, one-shot delivery, deterministic ids, bulk, payload and timestamp limits, restart durability |
| `test_manager_tasks.py` | Claim to completion, the retry and deferral ladders, coalescing, admission shedding, paging, and the recovery cases |
| `test_agent_upgrade.py` | The two upgrade routes against a stub repository: one fetch and one download per platform for a whole fleet, SHA-1 verification, the delivery gates, custom WPKs, the always-200 envelope, the disabled module and shutdown answering parked requests |
| `helpers/task_client.py` | The HTTP-over-UDS client, and the stub consumer whose answers each test scripts |
| `helpers/wpk_repo.py` | `StubWpkRepository`: a TCP server serving `versions` files and WPK bodies, counting every request |

## The stub consumer

`StubConsumer` is what makes the interesting cases reachable. The queue's behaviour is defined by
what a consumer does — answer, refuse, stall, or not be there at all — and each of those maps to a
different outcome:

| Stub answer | Outcome | Why it matters |
| --- | --- | --- |
| `200` | completed | the happy path |
| `500` | retryable | consumes an attempt, takes the backoff ladder |
| `409` | busy | consumes a *deferral*, not an attempt |
| `400` | terminal, or retryable for `agent_delete_indexer` | the type's own policy decides |
| socket absent | not ready | the boot race, which must not spend the retry budget |
| `stall=N` | timeout | a slow consumer, without waiting out a production deadline |
