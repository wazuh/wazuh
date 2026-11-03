# Router / Orchestrator Module

## Overview

The **Router** module is the event-processing core of the Wazuh Engine, responsible for ingesting security events into policy-based processing pipelines and providing a testing sandbox for policy validation. It is organized around the **Orchestrator** façade, which unifies two subsystems — production routing and testing — behind a single public API (`IOrchestratorAPI`).

**Production routing** dispatches incoming events through one or more priority-ordered policy environments using a multi-threaded worker pool, while **testing** processes events synchronously through a dedicated worker to return detailed trace/debug output.

## Architecture

```
                    ┌──────────────────────────────────────────────────────┐
                    │              IOrchestratorAPI                        │
                    │         (IRouterAPI + ITesterAPI)                    │
                    └─────────────────────┬────────────────────────────────┘
                                          │
                    ┌─────────────────────▼────────────────────────────────┐
                    │                Orchestrator                          │
                    │  - Lifecycle: start / stop / requestShutdown        │
                    │  - Config persistence (Store)                        │
                    │  - Event queue contention monitoring                 │
                    │  - Coordinates N RouterWorkers + 1 TesterWorker      │
                    └────────┬────────────────────────────┬────────────────┘
                             │                            │
              ┌──────────────▼──────────┐      ┌──────────▼──────────────┐
              │   RouterWorker (×N)     │      │    TesterWorker (×1)    │
              │   Thread + ProdQueue    │      │    Thread + TestQueue   │
              │   ┌───────────────────┐ │      │   ┌──────────────────┐  │
              │   │     Router        │ │      │   │     Tester       │  │
              │   │  Table<Entry>     │ │      │   │  map<name,Entry> │  │
              │   │  (priority-sorted)│ │      │   │                  │  │
              │   └───────┬───────────┘ │      │   └────────┬─────────┘  │
              └───────────┼─────────────┘      └────────────┼────────────┘
                          │                                 │
              ┌───────────▼─────────────────────────────────▼────────────┐
              │                    Environment                           │
              │          wraps bk::IController + hash                    │
              │         built by EnvironmentBuilder                      │
              └──────────────────────────────────────────────────────────┘
```

### Event Flow

1. **Production path**: An external caller invokes `postEvent()` on the Orchestrator, which pushes the `IngestEvent` (JSON + original string) into the shared `ProdQueue`. N `RouterWorker` threads compete to dequeue events. Each worker generates a timestamp (ISO 8601) and an event id (UUIDv4), indexes the raw event when the raw event indexer is enabled, parses it via `parseLegacyEvent`, sets `/@timestamp` and `/wazuh/event/id` (plus `/wazuh/cluster/name` and `/wazuh/cluster/node` when the manager configuration is loaded), and calls `Router::ingest()` which iterates the priority-sorted `Table` and feeds the event into every *enabled* `Environment`.

2. **Testing path**: A caller invokes `ingestTest()`, which wraps the event + options + callback into a `TestingTuple` and pushes it into the `TestQueue`. A single `TesterWorker` dequeues the tuple, stamps the event with `@timestamp` (ISO 8601) and `wazuh/event/id` (UUIDv4), subscribes to the requested asset traces on the `bk::IController`, runs the event through the pipeline, collects trace output, and delivers the result via the callback/future.

## Key Concepts

| Concept | Description |
|---|---|
| **Entry** | A named association between a policy namespace and a processing environment. Production entries have a *priority*; test entries have a *lifetime*. |
| **Environment** | A wrapper around `bk::IController` (the backend execution engine) plus a hash identifying the build. Created by `EnvironmentBuilder`. |
| **Table** | A priority-sorted collection (linked list + hash index) used by `Router` to guarantee event processing order. |
| **Worker** | A thread that drains a queue. `RouterWorker` drains production events; `TesterWorker` drains test events. Workers own their `Router`/`Tester` instance. |
| **Orchestrator** | Façade that replicates every route mutation across all N router workers and the single tester worker, persists state to the Store, and manages lifecycle. |
| **EntryConverter** | Serialization utility to convert entries to/from `json::Json` for Store persistence. |
| **EnvironmentBuilder** | Factory that uses `builder::IBuilder` + `bk::IControllerMaker` to compile a namespace's policy into a runnable `Environment`. |
| **Hot Swap** | Ability to atomically replace the namespace (policy) of a running route without downtime — the new environment is built lock-free, then swapped in under a write lock. |
| **Contention Monitoring** | The Orchestrator tracks production queue load (slots or bytes); when it stays at ≥ 90% for ≥ 10 minutes, it emits a warning with dropped-event counts, at most once every 10 minutes. |

## Directory Structure

```
router/
├── CMakeLists.txt
├── README.md
├── interface/router/           # Public interfaces (consumed by API layers)
│   ├── iapi.hpp                # IRouterAPI, ITesterAPI, IOrchestratorAPI
│   └── types.hpp               # prod::Entry/EntryPost, test::Entry/EntryPost/Options/Output, env::State/Sync
├── include/router/             # Public implementation header
│   └── orchestrator.hpp        # Orchestrator class + Options struct
├── src/                        # Internal implementation
│   ├── irouter.hpp             # IRouter internal interface
│   ├── itester.hpp             # ITester internal interface
│   ├── iworker.hpp             # IWorker<T> template interface
│   ├── router.hpp / .cpp       # Router — priority-based event dispatch
│   ├── tester.hpp / .cpp       # Tester — trace-enabled test execution
│   ├── worker.hpp / .cpp       # RouterWorker, TesterWorker
│   ├── table.hpp / .cpp        # Table<T> — priority-sorted container
│   ├── environment.hpp / .cpp  # Environment — bk::IController wrapper
│   ├── environmentBuilder.hpp  # EnvironmentBuilder — factory
│   ├── entryConverter.hpp/.cpp # EntryConverter — JSON serialization
│   └── orchestrator.cpp        # Orchestrator implementation
└── test/
    ├── mocks/router/           # GMock mocks (mockRouter.hpp, mockTester.hpp)
    └── src/
        ├── unit/               # Unit tests for each class
        └── component/          # Integration tests (router_test, tester_test)
```

## Public Interface

### `IOrchestratorAPI` ([iapi.hpp](interface/router/iapi.hpp))

Combines `IRouterAPI` and `ITesterAPI` into a single interface consumed by API handlers.

```cpp
using IngestEvent = std::pair<std::shared_ptr<const json::Json>, std::string>;

class IOrchestratorAPI : public IRouterAPI, public ITesterAPI {};
```

### `IRouterAPI` — Production Routes

| Method | Description |
|---|---|
| `postEntry(EntryPost)` | Create and enable a new production route |
| `deleteEntry(name)` | Remove a route from all workers |
| `getEntry(name)` / `getEntries()` | Query route metadata |
| `reloadEntry(name)` | Rebuild the environment from current policy |
| `changeEntryPriority(name, priority)` | Change processing order |
| `hotSwapNamespace(name, namespace)` | Atomically replace the policy namespace |
| `existsEntry(name)` | Check if a route exists |
| `postEvent(IngestEvent&&)` | Push an event into the production queue |

### `ITesterAPI` — Test Sessions

| Method | Description |
|---|---|
| `postTestEntry(EntryPost)` | Create and enable a test session |
| `deleteTestEntry(name)` | Remove a test session |
| `getTestEntry(name)` / `getTestEntries()` | Query test session metadata |
| `reloadTestEntry(name)` | Rebuild the test environment |
| `renameTestEntry(from, to)` | Rename a test session |
| `ingestTest(event, options)` | Process a test event (async via future) |
| `ingestTest(event, options, callback)` | Process a test event (callback-based) |
| `getAssets(name)` | List traceable assets in a test session |
| `getTestTimeout()` | Get the configured test timeout (milliseconds) |

### Types ([types.hpp](interface/router/types.hpp))

- **`env::State`**: `UNKNOWN`, `DISABLED`, `ENABLED`
- **`env::Sync`**: `UNKNOWN`, `UPDATED`, `OUTDATED`, `ERROR`
- **`prod::EntryPost`**: Creation parameters — name, namespace, priority (1–1000, `MAX_PRIORITY`), optional description
- **`prod::Entry`**: Runtime state — adds sync status, state, lastUpdate, hash
- **`test::EntryPost`**: Creation parameters — name, namespace, lifetime, optional description
- **`test::Entry`**: Runtime state — adds sync status, state, lastUse, hash
- **`test::Options`**: Test configuration — environment name, trace level (`NONE`/`ASSET_ONLY`/`ALL`; assets cannot be set with `NONE`), asset filter set
- **`test::Output`**: Test result — processed event + per-asset trace data

## Implementation Details

### Orchestrator Initialization

The `Orchestrator` constructor:

1. Validates the `Options` struct (thread count 0–128, non-null store/builder/controller maker/queues, timeout > 0); a failure throws `std::runtime_error`. The raw indexer is optional.
2. Creates a shared `EnvironmentBuilder` from the builder and controller maker.
3. Registers the router metrics (`router.queue.*`, `router.eps.{1m,5m,30m}`, `router.events.dropped`; the workers add `router.events.processed`), names in `fastmetrics/interface/fastmetrics/metric_names.hpp`.
4. Loads persisted router/tester configuration from the Store (`router/router/0`, `router/tester/0`).
5. Resolves the target pool size: `m_numThreads`, or the number of CPUs when it is `0` (`analysisd.orchestrator_threads`, default `0`).
6. Creates exactly **1** `RouterWorker` synchronously, initialized with the saved route table. Additional workers are deferred to `expandWorkerPool()` (see below).
7. Creates 1 `TesterWorker` initialized with saved test sessions.

### Deferred Worker Pool Expansion

`main.cpp` calls `expandWorkerPool()` from the content-synchronization scheduler task, right before each `cmsync` run, so the first synchronization mutates the complete pool; once the target size is reached the call is a no-op. It synchronously builds workers 2..N, each initialized from a snapshot of the first worker's route table.

The write lock (`m_syncMutex`) is held for the full snapshot → build → publish cycle of each worker. This serializes expansion against concurrent route mutations, which is the correct trade-off given that expansion happens once at startup. If a worker fails to initialize or start, the pool remains unchanged and the caller may invoke `expandWorkerPool()` again to retry.

### Multi-Worker Replication

Every route mutation (add, remove, rebuild, priority change, hot swap) is replicated across **all** N router workers via `forEachRouterWorker()`. This ensures every worker thread processes the same set of routes. After mutations, the configuration is persisted to the Store.

### Event Queue Contention Monitoring

`postEvent()` monitors the production queue load ratio, by slot count and by bytes (`analysisd.event_queue_max_bytes`):
- If either load is ≥ 90% (`CONTENTION_LOAD_PERCENT_THRESHOLD`), a contention window opens and failed pushes are counted (also in `router.events.dropped`, which never resets).
- After 600 s (`CONTENTION_WARNING_INTERVAL_SEC`) of sustained contention, `Event queue has remained contended for at least 600 seconds…` is logged as a warning, repeated at most every 600 s.
- When load drops below 90%, the window counters reset.

### Hot Swap

`hotSwapNamespace()` enables zero-downtime policy updates:
1. Validates the entry exists in the first worker (shared lock on the Orchestrator).
2. Under the Orchestrator's unique lock, for each router worker: the `Router` builds a new `Environment` without holding its own table lock, then swaps it in and enables the entry under its unique lock. Workers keep routing events meanwhile.
3. Persists the updated configuration.

### Router Ingestion

`Router::ingest()` iterates the priority-sorted `Table` under a shared lock. Each enabled `Environment` receives a **copy** of the event; the copy budget is the table size, so when every entry is enabled the last one receives the moved original instead of a copy.

### Test Execution

`Tester::ingestTest()`:
1. Looks up the test environment by name.
2. Subscribes to requested assets on the `bk::IController` to capture traces.
3. Runs the event through the controller (`ingestGet`).
4. Collects trace output into `test::Output` and unsubscribes.

The `TesterWorker` thread picks `TestingTuple` items from the test queue, stamps the event with `@timestamp` and `wazuh/event/id` (mirroring the production path), and invokes `Tester::ingestTest()`. The result is delivered to the caller via the callback. The `Orchestrator` exposes both a `std::future`-based and callback-based API for test ingestion.

### Table (Priority Container)

`internal::Table<T>` stores items in a `std::list` sorted by priority (ascending, so priority 1 runs first), with a `std::unordered_map` index for O(1) name lookup. It enforces uniqueness on both name and priority. Supports custom iterators for range-based iteration.

### EntryConverter (Persistence)

`EntryConverter` handles bidirectional conversion between `prod::Entry`/`test::Entry` and `json::Json`, enabling the Orchestrator to dump its state to the Store on every mutation and reload it on startup.

## CMake Targets

| Target | Type | Description |
|---|---|---|
| `router::irouter` | INTERFACE | Public interfaces and types (`iapi.hpp`, `types.hpp`) |
| `router::router` | STATIC | Full implementation (Orchestrator, Router, Tester, workers) |
| `router::mocks` | INTERFACE | GMock mocks for testing (test builds only) |
| `router_utest` | Executable | Unit tests (table, environment, environmentBuilder, router, tester, orchestrator, entryConverter) |
| `router_ctest` | Executable | Component/integration tests (router, tester) |

**Key dependencies**: `base`, `builder::ibuilder`, `bk::ibk`, `store::istore`, `fastqueue::ifastqueue`, `rawevtindexer::irawindexer`, `fastmetrics::ifastmetrics`, `cmstore::icmstore` (through `router::irouter`)

## Testing

Unit tests cover each internal class independently using GMock:

- **`table_test`**: Insert, erase, priority operations, free-priority search, iteration
- **`environment_test`**: Controller wrapping, hash tracking, ingestion
- **`environmentBuilder_test`**: Policy build, controller creation, error handling
- **`router_test`**: Entry CRUD, priority changes, event ingestion, hot swap
- **`tester_test`**: Entry CRUD, rename, test ingestion with traces, asset listing
- **`worker_test`**: RouterWorker/TesterWorker lifecycle, event processing, sentinel skipping, `@timestamp`/`wazuh.event.id` stamping
- **`orchestrator_test`**: Full lifecycle, multi-worker replication, store persistence, queue contention, worker pool expansion
- **`entryConverter_test`**: JSON ↔ Entry round-trip conversion

Component tests exercise the integrated subsystems with mock backends.

## Consumers

| Consumer | Usage |
|---|---|
| **`api/router`** | API handlers for production route management (CRUD + priority) |
| **`api/tester`** | API handlers for test session management and test execution |
| **`api/event`** | Event ingestion handler (`postEvent`) |
| **`api/cmcrud`** | Uses `ITesterAPI` to post a temporary test session that validates an imported policy with integrations |
| **`cmsync`** | Content synchronization — creates, hot-swaps and removes routes on policy changes |
| **`main.cpp`** | Engine entry point — creates `Orchestrator` with `Options`, calls `expandWorkerPool()` and manages lifecycle |
