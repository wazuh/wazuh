# Task Manager integration suite

Drives the real module through `task_manager_testtool`: the actual shared object, the actual socket,
the actual database. These tests exist to cover what the gtest suite structurally cannot — the wire,
real concurrency across worker threads, and recovery after the process is killed with rows still
claimed.

## Running

```bash
# Build the module and its testtool first.
cd src && make TARGET=server UNIT_TEST=1 -j$(nproc)

pip install -r wazuh_modules/task_manager/qa/requirements.txt
cd wazuh_modules/task_manager/qa
WAZUH_BUILD=../../../build pytest
```

`--testtool /path/to/task_manager_testtool` overrides the lookup. The suite skips rather than fails
when the binary is absent, so a unit-test-only job is not turned red by it.

## What is here

| File | Covers |
| --- | --- |
| `test_agent_tasks.py` | Creation, one-shot delivery, deterministic ids, bulk, payload and timestamp limits, restart durability |
| `test_manager_tasks.py` | Claim to completion, the retry and deferral ladders, coalescing, admission shedding, paging, and the recovery cases |
| `helpers/task_client.py` | The HTTP-over-UDS client, and the stub consumer whose answers each test scripts |

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
