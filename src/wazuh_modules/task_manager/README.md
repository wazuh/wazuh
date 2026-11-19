# task_manager

The manager's task queue, loaded by `wazuh-manager-modulesd` as `lib/libtask_manager.so`. It owns
`queue/tasks/tasks.db` outright and serves `queue/sockets/task-http.sock`. It does three jobs on one
socket and one database:

- **Agent tasks** — stored for an agent and handed out once when it polls (`active_response`,
  `remote_upgrade`, `agent_restart`, `agent_reload`). The manager never learns what came of one.
- **Manager tasks** — work the manager owes itself, claimed by a worker pool, executed and retired with
  an outcome: deleting an agent's indexer documents (`agent_delete_indexer`), an on-demand
  vulnerability scan (`vd_scan`), and the recurring disconnection sweep, old-agent deletion and daily
  log rotation. The manager log's size-triggered rotation runs here too, as a periodic action with no
  row.
- **Agent upgrades** — the two upgrade routes, whose output is a `remote_upgrade` agent task.

Three documentation layers cover this module, each with its own job:

- **This README** — the developer's map: the [requirements](#requirements) and where each one is
  pinned, the [design decisions](#design-decisions) and the constraint behind each, the
  [layout](#layout), the [C ABI](#c-abi), what [moves together](#what-moves-together) and the
  [test map](#tests).
- **[`docs/ref/modules/task_manager/`](../../../docs/ref/modules/task_manager/README.md)** — the
  operator- and integrator-facing reference:
  [overview and architecture](../../../docs/ref/modules/task_manager/README.md),
  [manager tasks](../../../docs/ref/modules/task_manager/manager-tasks.md) (states, retry and
  deferral, ownership, retention),
  [recurring manager tasks](../../../docs/ref/modules/task_manager/schedules.md),
  [agent upgrades](../../../docs/ref/modules/task_manager/agent-upgrades.md),
  [API reference](../../../docs/ref/modules/task_manager/api-reference.md),
  [configuration](../../../docs/ref/modules/task_manager/configuration.md) and
  [metrics](../../../docs/ref/modules/task_manager/metrics.md). Defaults, status codes, log lines and
  the outcome table live there and are not repeated here.
- **[`qa/README.md`](qa/README.md)** — the integration suite that drives the real `.so` over the real
  socket, including `kill -9` recovery.

The two consumers of the routed manager tasks have their own READMEs:
[`inventory_sync_server`](../inventory_sync_server/README.md) executes both
(`POST /_internal/agents/delete`, `POST /_internal/vd/scan`), and [`os_auth`](../../os_auth/README.md)
explains why an agent removal becomes an `agent_delete_indexer` row instead of a network call.

## Requirements

Each row is behaviour the code demonstrates today, with the test that pins it. `TaskManager` tests
are in `test/unit/` (binary `task_manager_utest`); `qa/` tests drive the built module.

### Functional (RF)

| # | Requirement | Where |
|---|---|---|
| RF-1 | Store agent tasks and hand each one out once: `POST /v1/tasks/pending` reads and marks `delivered` in one transaction | `SqliteTaskStore::takePendingAgentTasks` (`src/storage/sqliteTaskStore.cpp`); `StoreTest.TakingPendingAgentTasksMarksThemDeliveredInOnePass`, `ApiTest.TakingPendingTasksReturnsThemOnceAndHandsBackParsedPayloads`, `qa/test_agent_tasks.py` |
| RF-2 | An agent task's id is deterministic: the first 16 bytes of SHA-256 over `[source_id:]agent_id:task_type:create_time`, formatted 8-4-4-4-12, so a repeated create is one row | `taskId::forAgentTask` (`src/model/taskId.cpp`); `TaskId.AgentTaskIdMatchesItsGoldenVectors`, `StoreTest.AgentTaskCreationIsIdempotent`, `ApiTest.TheSameLogicalRequestProducesTheSameId` |
| RF-3 | An idle poll never reaches SQLite: only the absence of tasks is cached per agent, and a create evicts the entry | `src/cache/pendingCache.hpp`; `PendingCache.OnlyEverRecordsAbsence`, `ApiTest.TheNegativeCacheAnswersIdlePollsWithoutTouchingTheStore`, `ApiTest.CreatingATaskEvictsTheAgentFromTheNegativeCache` |
| RF-4 | A manager task is claimed exactly once, executed by a registered handler and retired with the outcome it reports | `src/execution/executor.cpp`; `ExecutorTest.RunsAPendingTaskAndRetiresItCompleted`, `ExecutorTest.RunsEveryPendingTaskExactlyOnce`, `StoreTest.ClaimIsExactlyOnceUnderConcurrency` |
| RF-5 | Map each outcome onto two ladders: retry backoff (costs an attempt) and deferral (costs a deferral), each doubling to a shared cap; exhausting either budget dead-letters | `src/registry/retryPolicy.cpp`, `src/registry/httpResultMapper.cpp`; the `RetryPolicy`, `ApplyResult` and `HttpResultMapper` suites in `test/unit/policies_test.cpp` |
| RF-6 | `agent_delete_indexer` never gives up: no attempt budget, no deferral budget, and a `4xx` re-queues instead of failing | its descriptor in `src/registry/builtinTypes.cpp` (`maxAttempts`/`maxDefer` = `UNBOUNDED`, `allowTerminalFailure = false`); `BuiltinRegistry.AgentDeletionNeverGivesUp`, `ApplyResult.ATypeThatMayNotFailTerminallyIsRequeuedInstead`, `ApplyResult.AnUnboundedTypeNeverDeadLetters` |
| RF-7 | `vd_scan` coalesces per agent, runs one at a time, has the default attempt and deferral budgets and may fail terminally on a `4xx` | its descriptor in `src/registry/builtinTypes.cpp`; `BuiltinRegistry.OnlyTheScanCoalesces`, `StoreTest.CoalescingReturnsTheSurvivingIdNotTheRequestedOne`, `StoreTest.CoalescingIsPerTypeSoTwoDeletionsNeverCollapse` |
| RF-8 | Each built-in type's admission bound refuses a create with `503 queue_full` once reached; the descriptor, not the request, sets it | `ApiHandlers::createManagerTask` (`src/http/apiHandlers.cpp`); `StoreTest.TheAdmissionBoundIsExact`, `ApiTest.TheDescriptorDecidesTheAdmissionBoundNotTheRequest`, `ApiTest.TheDescriptorDecidesCoalescingNotTheRequest` |
| RF-9 | A row left `claimed` by a worker that is not running it is returned to `pending` without charging an attempt — at startup for dead processes, then every sweep for this process's own workers | `src/execution/sweeper.cpp`, `src/execution/ownership.cpp`; `SweeperTest.ReclaimsARowLeftClaimedByADeadProcess`, `SweeperTest.ReclaimingDoesNotChargeAnAttempt`, the `Ownership` suite in `test/unit/schedule_test.cpp` |
| RF-10 | A manager task of a type this build does not register is accepted (`200`) and stays `pending`, up to an admission bound of its own (`UNKNOWN_TYPE_MAX_PENDING`, 100, unless the request names a positive `max_pending`; beyond it `503 queue_full`); the startup sequence retires every such row `failed` with `unknown task type` | `ApiHandlers::createManagerTask` (`src/http/apiHandlers.cpp`); `Sweeper::reapOrphanedTypes`, called only from `Scheduler::runStartupSequence` (`src/schedule/scheduler.cpp`); `ApiTest.AnUnknownTypeMayCarryItsOwnPolicy`, `ApiTest.AnUnknownTypeWithNoBoundOfItsOwnGetsTheDefaultBound`, `ApiTest.ARequestCannotLiftTheBoundOfAnUnknownType`, `StoreTest.OrphanedTypesAreDiscoverableAndRetirable`, `SweeperTest.ReclaimsARowOfAnUnknownTypeSoTheReaperCanRetireIt` |
| RF-11 | Run three recurring schedules — disconnection sweep and old-agent deletion on the master only, daily rotation on every node — plus the size-rotation action every 60 s; a scheduled run's id is derived from its slot | `buildBuiltinSchedules`, `makeSizeRotationAction` (`src/registry/builtinTypes.cpp`), `src/schedule/`; the `BuiltinSchedules`, `SweepPeriod`, `Cadence`, `StartupNextRun` and `NodeScope` suites, `TaskId.ScheduledRunIdMatchesItsGoldenVector` |
| RF-12 | Serve agent upgrades: `POST /v1/agents/upgrade` and `/v1/agents/upgrade-custom`, answered from a worker pool with a per-agent envelope, writing `remote_upgrade` agent tasks in one transaction per batch | `src/upgrade/`; the `Upgrade*`, `OrchestratorTest`, `ServiceTest` and `UpgradeApiTest` suites, `qa/test_agent_upgrade.py` |
| RF-13 | Expose liveness and the module's metrics on the same socket (`GET /v1/health`, `GET /v1/metrics`) | `src/http/httpServer.cpp`, every name in `src/metrics/metricNames.hpp`, instruments in `src/metrics/taskMetrics.cpp`; `qa/test_agent_tasks.py` |
| RF-14 | A create is counted per registered type and result, and every unregistered type under the one `unknown` bucket; all those counters exist at `0` before the first request, and no request names a metric | `TaskMetrics::taskCreated`, names in `src/metrics/metricNames.hpp`; `TaskMetricsTest.EveryCreateCounterExistsBeforeTheFirstRequest`, `TaskMetricsTest.UnregisteredTypesShareOneBucketAndMintNoMetric`, `TaskMetricsTest.TheCreateRouteCountsAnUnknownTypeInTheBucket` |
| RF-15 | Every `retired` and `handler.outcome` counter exists at `0` from construction for each registered type and the `unknown` bucket; a non-terminal status is never counted | `TaskMetrics::createTypeCounters`; `TaskMetricsTest.EveryRetiredAndOutcomeCounterExistsBeforeTheFirstEvent`, `TaskMetricsTest.AnUnregisteredTypeReachingRetiredOrOutcomeLandsInTheBucket`, `TaskMetricsTest.ANonTerminalStatusIsNotCounted` |

### Non-functional (RNF)

| # | Requirement | Where |
|---|---|---|
| RNF-1 | No polling: the scheduler sleeps until the earliest due row or timer, and a create through the socket wakes the executor at once | `Scheduler::loop`, `Executor::retireType` (`src/execution/executor.cpp`); `ApiTest.CreatingAManagerTaskWakesTheExecutorImmediately`, `StoreTest.TheEarliestPendingAttemptDrivesTheSchedulersSleep`, `ExecutorTest.AnEmptyClaimDoesNotSwallowAConcurrentNotification` |
| RNF-2 | A cluster role that cannot be read is never treated as master | `is_worker` contract in `include/task_manager.h`, `src/schedule/cadence.cpp`; `NodeScope.MasterScopeRequiresAnExplicitMasterAndUnknownIsNotOne` |
| RNF-3 | A handler that throws costs that task one retryable outcome, never the worker | `ExecutorTest.AHandlerThatThrowsDoesNotKillTheWorker` |
| RNF-4 | Shutdown starts nothing it cannot finish: a task claimed as the module stops is left `claimed`, unstarted, and in-flight rows are never released on the way out — the next start's sweep reclaims them (RF-9) | the stop check between claim and handler in `Executor` (`src/execution/executor.cpp`), the `task_manager_stop` contract in `include/task_manager.h`, the teardown order in `src/taskManagerFacade.hpp`; `ExecutorTest.StoppingLeavesAnInFlightRowClaimedForTheNextBoot` |
| RNF-5 | The database stays bounded: retention removes only terminal rows (dead letters last), the WAL does not grow across scheduler passes, and freed pages return to the filesystem incrementally | `src/storage/sqliteTaskStore.cpp`; `StoreTest.RetentionRemovesOnlyTerminalRows`, `StoreTest.TheCeilingEvictsCompletedRowsBeforeDeadLetters`, the `WalStoreTest` and `CompactionTest` suites |
| RNF-6 | The `.so` links no `libwazuh`; everything it needs from it arrives through the host-ops table | `CMakeLists.txt` (link list and its comment), `include/task_manager.h` |
| RNF-7 | Every request body is bounded: the server-wide cap is never below the largest per-route cap, and the manager-task create route admits one whole `max_payload_bytes` | `config.maxBodySize` in `HttpServer::start` (`src/http/httpServer.cpp`), `createMaxBodyBytes` in `src/taskManagerFacade.hpp`; `ApiTest.RejectsAnOversizedPayload` |

## Design decisions

Numbered in the order they are listed here; append new ones, never renumber. Each rationale is the one
the cited code comment records.

| # | Decision | Why |
|---|---|---|
| D1 | **A manager task is retired only when its consumer reports the work done**, and both consumer routes answer at completion, never at admission | A row is the memory of an obligation that must survive a restart and an indexer outage; a route that answered at admission would leave the row `completed` while the work was still queued elsewhere (`ROUTE_*` in `src/registry/builtinTypes.hpp`; [why a queue at all](../../../docs/ref/modules/task_manager/manager-tasks.md#why-a-queue-at-all)) |
| D2 | **One worker pool, isolated by a per-group concurrency cap in each descriptor** — not a thread or lane per type. Only the two log rotations share a group | The rotations rewrite the same files and must never overlap; nothing else conflicts, so nothing else shares (`GROUP_ROTATION` in `src/registry/builtinTypes.hpp`). Adding a type is a descriptor plus a handler, with no change to the executor, scheduler, store or schema |
| D3 | **`agent_delete_indexer` has no attempt budget, no deferral budget and no terminal failure, and none of the three is an operator knob** | Once `client.keys` is written the agent is gone and nobody will ask again, so the row is the only record of the obligation; a finite budget or a re-enabled terminal failure would reintroduce the orphaned indexer documents the queue exists to prevent (comment on the descriptor in `src/registry/builtinTypes.cpp`) |
| D4 | **`manager_task_delete_timeout` must exceed `manager_task_vd_scan_timeout`, or the registry refuses to build** | A scan holding an agent parks that agent's deletion behind it in the consumer's per-agent queue; an equal or shorter deletion deadline would expire while parked (`buildBuiltinRegistry`; `BuiltinRegistry.TheDeleteDeadlineMustExceedTheScanDeadline`) |
| D5 | **Scans coalesce per agent; deletions never do** | A second scan request for an agent with one pending is the same work; two deletions of one agent are two distinct obligations (`src/registry/builtinTypes.cpp`) |
| D6 | **The descriptor, not the request, decides coalescing and the admission bound.** A request may carry them only for a type this build does not register | A producer that could choose either could bypass the bound that protects the queue, and for the deletion type reintroduce orphaned documents; the override exists so a test fixture can register a synthetic type (`ApiHandlers::createManagerTask`) |
| D7 | **Task type names are persisted strings.** An unregistered type is accepted and retired at the next start, not refused at create | The names live in `MANAGER_TASKS.TASK_TYPE` and `MANAGER_TASK_SCHEDULES`; renaming one strands every existing row of that type until the orphaned-type reaper runs (`PERSISTED STRINGS` in `src/registry/builtinTypes.hpp`). The sweep also releases a claimed row of an unknown type, because the reaper only looks at pending rows and a claimed one would otherwise be stuck forever (`src/execution/sweeper.cpp`) |
| D8 | **Identity is per task kind: deterministic for a creator that can run twice for one event, random for one that can be called twice meaning two different things.** Both recipes the module derives stay byte-identical to their C counterparts | The spawn loop's crash safety is a primary-key collision, and authd treats a collision as "already recorded"; changing a recipe silently breaks both (`src/model/taskId.hpp`). `manager_task_id_agent_delete` (authd's journal sequence) and `manager_task_id_random` (`vd_scan`) are producer-side, in `src/shared/src/manager_task_op.c`, and only received here |
| D9 | **A scheduled run's id is keyed on its slot, not on the moment it was spawned** | A crash between inserting the instance and advancing `NEXT_RUN_AT` re-derives the same id on retry, so the double spawn is a no-op without a cross-table transaction (`taskId::forScheduledRun`) |
| D10 | **The agent-task id keeps its legacy shape**: truncated to 16 bytes, and an empty `source_id` aliases an omitted one | Changing either would change the ids of tasks already in flight (`taskId::forAgentTask` in `src/model/taskId.hpp`) |
| D11 | **`create` and `claim` commit inline; outcomes, re-queues and retention are group-committed** | authd drops its journal lines when the create returns, so an `ok` that is only buffered would move the orphan window instead of closing it (`createManagerTask` in `src/storage/sqliteTaskStore.cpp`). A lost outcome write is already tolerated: the row stays claimed, the sweep reclaims it and every handler is idempotent |
| D12 | **A reclaimed row is re-queued exactly as it was: no attempt is charged** | A crashed worker is not the task failing; charging it would let a manager crash-looping for an unrelated reason dead-letter healthy work (`src/execution/sweeper.cpp`) |
| D13 | **What only `libwazuh` implements — cluster role, the authd protocol, log rotation, three wazuh-db agent queries — arrives as a host-ops table of function pointers** | modulesd links the static `libwazuh`, so a `.so` that linked it too would put a second copy of its globals in one process. The agent queries use the shim's bounded wazuh-db client because `SocketDBWrapper` waits with no timeout, and an unbounded wait would hold an executor slot forever (`include/task_manager.h`) |
| D14 | **Fields whose zero means something take `-1` for "zero" and keep `0` for "default"** (`[-1 disables]` in the header); the shim converts a configured zero | A zero-initialised config must mean every default, because every embedder assumes it (the testtool memsets the struct); reading zero as "disabled" would silently turn off log rotation and every admission bound (`include/task_manager.h`, `valueOrAllowingZero` in `src/taskManagerFacade.hpp` and `src/registry/builtinTypes.cpp`) |
| D15 | **A failed `task_manager_start()` is fatal to modulesd** (`mterror_exit`) | A manager whose task queue silently did not start loses agent deletions: authd records the intent and nothing executes it (`src/wazuh_modules/src/wm_task_manager.c`) |
| D16 | **Size-triggered rotation is a periodic action, not a task row** | It would be about 1440 rows a day for work that is idempotent, instantaneous and harmless to miss (`makeSizeRotationAction`) |
| D17 | **A sweep that applies a window as an age polls at a quarter of it, floored at 60 s and capped at 300 s (disconnection) or 3600 s (old-agent deletion), never coarser than the window** | With the period equal to the window, the real transition landed anywhere in `[W, 2W]`; a quarter bounds the overshoot at 25 %, the floor keeps a short window from becoming a hot loop against wazuh-db, and the ceilings cap absolute lateness by each run's cost (`SWEEP_PERIOD_DIVISOR` in `src/registry/builtinTypes.hpp`) |
| D18 | **Teardown is not construction reversed**: stop accepting, stop the scheduler, stop the executor, flush the store, stop the HTTP server, close the store | Stopping the server before the executor would tear down the runtime while a handler might still answer through a responder; flushing before the executor stops would flush a batch still being added to (class comment in `src/taskManagerFacade.hpp`). The facade releases a partly built module the same way when `start()` throws |
| D19 | **The upgrade routes are always registered; `upgrade_enabled` is checked per request** | With the socket shared there is nothing to leave unbound, and a disabled module answering every agent with a clear code beats a route that `404`s (`buildUpgradeSubsystem` in `src/taskManagerFacade.hpp`) |
| D20 | **A type this build does not register is never admitted unbounded: it gets a fixed admission bound of 100 pending rows (`UNKNOWN_TYPE_MAX_PENDING`), which a request may replace with a positive `max_pending` but never lift.** The reaper still runs only at startup | Nothing claims such a row, only the next start retires it (D7) and `manager_task_max_rows` evicts terminal rows only, so a producer that misspelt its type would otherwise grow `MANAGER_TASKS` until a restart. Bounding admission keeps D6's fixture override and D7's accept-then-retire contract, and refuses with the `503 queue_full` producers already handle for the built-in bounds; retiring unknown types on every sweep instead would fail a fixture's rows under it within a minute and turn the reaper from a startup step into a periodic one. The bound is per type name, so it caps a fixed misspelt literal, not a producer that invents a new name per request (`src/http/apiHandlers.hpp`) |
| D21 | **Unregistered types are counted under one `unknown` bucket, and the create counters are pre-created for the closed set of registered types times create results.** A registered type may not be named `unknown`: `TaskMetrics` throws, failing the start | The create route admits any type name, so a counter named after the request would mint a metric per misspelt or invented type for the life of the process, which nothing removes. The registry is fixed at start, so the set is closed; pre-creating it also takes the lock and the lookup off the create path. The facade builds `TaskMetrics` after the registry for this reason. `retired.*` and `handler.outcome.*` stay resolved on first use, because only claimed rows of registered types reach them (`src/metrics/metricNames.hpp`, `src/metrics/taskMetrics.cpp`) |
| D22 | **Every metric name is a constant in `src/metrics/metricNames.hpp`; no call site spells one.** A per-type family is a `_PREFIX` completed with the type (and a `.<suffix>`) at its one call site | The names are read verbatim by the [metrics catalog](../../../docs/ref/modules/task_manager/metrics.md), the benchmark scrapers and dashboards, so they are a contract; one header makes a rename a visible, single-file change, as the `wazuh-module-contracts` rules require (`src/metrics/metricNames.hpp`) |
| D23 | **The `retired` and `handler.outcome` families are pre-created too, per registered type and the `unknown` bucket, times every terminal status and every outcome; `TaskMetrics` holds no lock and formats no name after construction.** An unregistered type reaching them counts under `unknown`, and a non-terminal status passed to `taskRetired()` is dropped | Only the executor feeds them, with claimed rows of registered types and terminal statuses, so neither fallback fires today; counting into the bucket rather than throwing keeps a metrics call from ever failing a task, and keeps the never-format-per-event rule unconditional. The cost is eleven always-zero `unknown` counters (`src/metrics/taskMetrics.cpp`). This extends D21, whose last sentence no longer holds |

## Layout

```
task_manager/
├── include/task_manager.h       # C ABI: config struct, host-ops table, start/stop (see C ABI)
├── src/
│   ├── taskManager.cpp          # extern "C" entry points -> facade
│   ├── taskManagerFacade.hpp    # build and teardown order, config resolution, queue metrics
│   ├── taskManagerLog.hpp       # module log tags (:executor, :scheduler, :http, :upgrade)
│   ├── model/                   # Task, outcomes, taskId (the id recipes, D8-D10)
│   ├── storage/                 # schema.hpp (DDL + SCHEMA_VERSION), statements, SqliteTaskStore
│   ├── registry/                # TaskTypeDescriptor, TaskRegistry, builtinTypes (TYPE_*, D2-D7),
│   │                            #   retryPolicy (the two ladders), httpResultMapper (status -> outcome)
│   ├── execution/               # Executor (worker pool + group caps), ownership, Sweeper (reclaim,
│   │                            #   orphaned-type reaper, watchdog)
│   ├── schedule/                # cadence arithmetic, Scheduler (the one timer thread)
│   ├── handlers/                # HttpHandler + udsHttpClient (routed types), localHandlers
│   │                            #   (disconnect sweep, old-agent deletion, daily rotation)
│   ├── host/                    # IHostOps over the C host-ops table
│   ├── http/                    # route table (httpServer) and per-route logic (apiHandlers)
│   ├── cache/                   # the negative pending-task cache
│   ├── metrics/                 # metricNames (every metric name), taskMetrics (the instruments)
│   └── upgrade/                 # agent upgrades: API, batch orchestrator, WPK repository and caches
├── test/                        # task_manager_utest (unit/) and its doubles (mocks/)
├── testtool/                    # task_manager_testtool: runs the real .so for qa/
└── qa/                          # integration suite (pytest), see qa/README.md
```

Subsystems include each other by prefix (`"storage/..."`, `"execution/..."`): `src/` is on the include
path (`CMakeLists.txt`). The library is pinned to C++17 because its transport,
`wazuh_uds_http_server`, declares a strict C++17 floor (`CMakeLists.txt`).

## C ABI

`include/task_manager.h` is the only header modulesd's shim, `src/wazuh_modules/src/wm_task_manager.c`,
sees. The shim `dlopen`s `libtask_manager.so`, resolves `task_manager_start` and `task_manager_stop`,
fills `task_manager_config_t` (absolute paths, the `<task-manager>` options, the `global` and `remote`
values the module needs, and every internal option already resolved by
`src/config/src/wmodules-task-manager.c`) and a `task_manager_host_ops_t`, then calls start. Start
binds the socket, opens the database, starts the module's own threads and returns; the modulesd thread
exits right after.

Rules the header states and the code relies on:

- **Append only.** Fields are appended to both structs, never inserted or reordered.
- **Sentinels.** An int `<= 0` or an empty string means "use the module default", which lives only in
  the C++ module; the `[-1 disables]` fields are the exception (D14). `remoted_config_read` is a third
  variant: an explicit validity flag, because both meaningful values of `remoted_verification_mode` are
  `<= 0`.
- **Host ops are optional.** A `NULL` pointer disables the feature that needs it and is logged once at
  start. They are called at schedule cadence or from handlers, never on the HTTP hot path.
- **Stop is idempotent** and leaves in-flight rows `claimed` for the next start (RNF-4).

## What moves together

| Change | Files |
|---|---|
| A new manager task type | `TYPE_*` and its descriptor in `src/registry/builtinTypes.hpp`/`.cpp`, a handler (or a consumer route), the producer's literal (`MANAGER_TASK_TYPE_AGENT_DELETE` in `src/shared/include/manager_task_op.h`; `VD_SCAN_TASK_TYPE` in `src/wazuh_modules/vulnerability_scanner/src/vulnerabilityScanner.cpp`), the producer's id derivation, and the [task types table](../../../docs/ref/modules/task_manager/manager-tasks.md#task-types). A misspelt producer literal is admitted up to 100 pending rows, then refused `503 queue_full`, and retired at the next start (RF-10, D20); nothing fails at build |
| Renaming a `TYPE_*` or schedule id | Do not: the strings are persisted (D7) |
| An id recipe | `src/model/taskId.cpp` and `src/shared/src/manager_task_op.c` together, byte for byte. A golden vector pins only the scheduled-run recipe on both sides (`TaskId.ScheduledRunIdMatchesItsGoldenVector` and `test_id_schedule_matches_the_task_managers_own_vector` in `src/unit_tests/shared/test_manager_task_op.c`); the agent-delete vector is asserted only on the C side |
| A consumer route or socket | `ROUTE_*` in `src/registry/builtinTypes.hpp` and the consumer ([`inventory_sync_server`](../inventory_sync_server/README.md)). A moved route makes `agent_delete_indexer` rows retry forever (D3) |
| A table's shape | `src/storage/schema.hpp` (bump `SCHEMA_VERSION`) and a step in `SqliteTaskStore::migrate()`: the DDL is `CREATE ... IF NOT EXISTS` and cannot alter an existing table |
| A field of the C ABI | `include/task_manager.h` (append), `wm_task_manager_fill_config` in the shim, the reader in `src/config/src/wmodules-task-manager.c`, the facade's resolution, and the [configuration reference](../../../docs/ref/modules/task_manager/configuration.md) |
| An agent task type | the producer and the agent: `src/client-agent/https_client/src/taskBatch.hpp`, and `src/remoted/src/legacy_task_delivery.c` for agents served by the legacy poller. The store accepts any non-empty type |
| A route or a metric | `src/http/httpServer.cpp` or `src/metrics/taskMetrics.cpp`, the name in `src/metrics/metricNames.hpp` (a rename breaks the benchmark scrapers and dashboards), the [API reference](../../../docs/ref/modules/task_manager/api-reference.md) or [metrics catalog](../../../docs/ref/modules/task_manager/metrics.md), and the `wazuh-module-contracts` skill's rules |

## Tests

| Suite | What | ctest label | CI |
|---|---|---|---|
| `task_manager_utest` (`test/unit/`, 18 files) | store, registry, policies, executor and sweeper, scheduling and ids, local handlers, host ops, API, metrics, the upgrade path | `task_manager_utest` | [5_testunit_taskmanager.yml](../../../.github/workflows/5_testunit_taskmanager.yml): a coverage job (lcov floor **65**, functions not validated) and an ASAN job; both `allowed_skips: 0`, no valgrind |
| `qa/` (pytest over `task_manager_testtool`) | the wire, real worker concurrency, recovery after `kill -9`, agent upgrades against a stub repository — see [qa/README.md](qa/README.md) | — | [5_testintegration_taskmanager.yml](../../../.github/workflows/5_testintegration_taskmanager.yml), with `-rs`; every case skips (exit 0) when the testtool is not built |
| `test_manager_task_op` (cmocka, `src/unit_tests/shared/`) | the producer client and its id golden vectors | — | [5_testunit_linux-win.yml](../../../.github/workflows/5_testunit_linux-win.yml) (manager leg) |
| `test_log_rotate` (cmocka, `src/unit_tests/shared/`) | `src/shared/src/log_rotate.c`, which the host ops call for both rotations | — | [5_testunit_linux-win.yml](../../../.github/workflows/5_testunit_linux-win.yml) |

The coverage floor sits below the 90 % default on purpose: the facade, the C entry points, the route
table and the libcurl consumer client are reached only by binding a socket and starting the pool, which
the `qa/` harness does and the coverage job does not measure (comment on the coverage step in
`5_testunit_taskmanager.yml`). Valgrind is off because the executor tests assert on timing-bounded
concurrent behaviour that fails under Valgrind's serialized execution; ASAN covers memory safety (same
workflow). Formatting is checked by
[5_codelinter_clangformat.yml](../../../.github/workflows/5_codelinter_clangformat.yml), which covers
`src/wazuh_modules/task_manager/**/*.[ch]pp`.

`task_manager_utest` links the module's `.so` instead of recompiling its sources, because
`Log::GLOBAL_LOG_FUNCTION` has hidden visibility and a copy compiled into the test binary would be a
different object from the one the module logs through (`test/CMakeLists.txt`).
