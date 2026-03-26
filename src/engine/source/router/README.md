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
                    │  - Lifecycle: start / stop / cleanup                 │
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

1. **Production path**: An external caller invokes `postEvent()` on the Orchestrator, which pushes the `IngestEvent` (JSON + original string) into the shared `ProdQueue`. N `RouterWorker` threads compete to dequeue events. Each worker optionally indexes the raw event, parses it via `parseLegacyEvent`, and calls `Router::ingest()` which iterates the priority-sorted `Table` and feeds the event into every *enabled* `Environment`.

2. **Testing path**: A caller invokes `ingestTest()`, which wraps the event + options + callback into a `TestingTuple` and pushes it into the `TestQueue`. A single `TesterWorker` dequeues the tuple, subscribes to the requested asset traces on the `bk::IController`, runs the event through the pipeline, collects trace output, and delivers the result via the callback/future.

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
| **Contention Monitoring** | The Orchestrator tracks production queue load; when it exceeds 90% capacity for ≥ 10 minutes, it emits a warning with dropped-event counts. |

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
    ├── mocks/router/           # Mock interfaces (mock_iapi.hpp)
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
| `postEvent(IngestEvent)` | Push an event into the production queue |

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
| `getTestTimeout()` | Get the configured test timeout |

### Types ([types.hpp](interface/router/types.hpp))

- **`env::State`**: `UNKNOWN`, `DISABLED`, `ENABLED`
- **`env::Sync`**: `UNKNOWN`, `UPDATED`, `OUTDATED`, `ERROR`
- **`prod::EntryPost`**: Creation parameters — name, namespace, priority (1–1000), description
- **`prod::Entry`**: Runtime state — adds sync status, state, lastUpdate, hash
- **`test::EntryPost`**: Creation parameters — name, namespace, lifetime, description
- **`test::Entry`**: Runtime state — adds sync status, state, lastUse, hash
- **`test::Options`**: Test configuration — environment name, trace level (`NONE`/`ASSET_ONLY`/`ALL`), asset filter set
- **`test::Output`**: Test result — processed event + per-asset trace data

## Implementation Details

### Orchestrator Initialization

The `Orchestrator` constructor:

1. Validates the `Options` struct (thread count 0–128, non-null pointers, timeout > 0).
2. Creates a shared `EnvironmentBuilder` from the builder and controller maker.
3. Loads persisted router/tester configuration from the Store (`router/router/0`, `router/tester/0`).
4. Creates N `RouterWorker` instances (defaults to `hardware_concurrency` if thread count is 0), each initialized with the saved route table.
5. Creates 1 `TesterWorker` initialized with saved test sessions.

### Multi-Worker Replication

Every route mutation (add, remove, rebuild, priority change, hot swap) is replicated across **all** N router workers via `forEachRouterWorker()`. This ensures every worker thread processes the same set of routes. After mutations, the configuration is persisted to the Store.

### Event Queue Contention Monitoring

`postEvent()` monitors the production queue load ratio:
- If load ≥ 90%, a contention window opens and dropped events are counted.
- After 10 minutes of sustained contention, a `LOG_WARNING` is emitted.
- When load drops below 90%, counters reset.

### Hot Swap

`hotSwapNamespace()` enables zero-downtime policy updates:
1. Validates the entry exists (shared lock).
2. For each router worker: builds a new `Environment` without any lock, then atomically swaps it under a unique lock.
3. Persists the updated configuration.

### Router Ingestion

`Router::ingest()` iterates the priority-sorted `Table` under a shared lock. Each enabled `Environment` receives a **copy** of the event, except the last one which receives the moved original — avoiding unnecessary allocations.

### Test Execution

`Tester::ingestTest()`:
1. Looks up the test environment by name.
2. Subscribes to requested assets on the `bk::IController` to capture traces.
3. Runs the event through the controller (`ingestGet`).
4. Collects trace output into `test::Output` and unsubscribes.

The `TesterWorker` thread picks `TestingTuple` items from the test queue and invokes the callback with the result. The `Orchestrator` exposes both a `std::future`-based and callback-based API for test ingestion.

### Table (Priority Container)

`internal::Table<T>` stores items in a `std::list` sorted by priority (ascending), with a `std::unordered_map` index for O(1) name lookup. It enforces uniqueness on both name and priority. Supports custom iterators for range-based iteration.

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

**Key dependencies**: `base`, `builder::ibuilder`, `bk::ibk`, `store::istore`, `fastqueue::ifastqueue`, `rawevtindexer::irawindexer`, `cmstore::icmstore`

## Testing

Unit tests cover each internal class independently using GMock:

- **`table_test`**: Insert, erase, priority operations, free-priority search, iteration
- **`environment_test`**: Controller wrapping, hash tracking, ingestion
- **`environmentBuilder_test`**: Policy build, controller creation, error handling
- **`router_test`**: Entry CRUD, priority changes, event ingestion, hot swap
- **`tester_test`**: Entry CRUD, rename, test ingestion with traces, asset listing
- **`orchestrator_test`**: Full lifecycle, multi-worker replication, store persistence, queue contention
- **`entryConverter_test`**: JSON ↔ Entry round-trip conversion

Component tests exercise the integrated subsystems with mock backends.

## Consumers

| Consumer | Usage |
|---|---|
| **`api/router`** | REST API handlers for production route management (CRUD + priority) |
| **`api/tester`** | REST API handlers for test session management and test execution |
| **`api/event`** | Event ingestion API endpoint |
| **`api/cmcrud`** | Configuration management handlers interfacing with router state |
| **`cmsync`** | Configuration synchronization — triggers route rebuilds on policy changes |
| **`main.cpp`** | Engine entry point — creates `Orchestrator` with `Options` and manages lifecycle |
