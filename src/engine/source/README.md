# Wazuh Engine — Source Tree Architecture

`wazuh-engine` is the decoding, enrichment and routing engine of the Wazuh manager (it ships as the `wazuh-manager-analysisd` daemon). It receives raw security events from `remoted` and external producers, parses them into the **Wazuh Common Schema (WCS)** using user-defined **decoders**, enriches them (GeoIP, IOC, KVDB lookups), runs them through one or more **policies**, and forwards the resulting normalized JSON documents to the Wazuh Indexer (and optional file outputs).

The engine can also run standalone (`WAZUH_ENGINE_STANDALONE=true`) for development, testing or if run inside wazuh-indexer as a standalone content processor/validator.

This README is the **developer / source-tree** view: what each directory does, how modules depend on each other, and how the process is wired together at startup. For operator-facing documentation (configuration, ruleset authoring, CLI usage), see the [user manual](../../../docs/ref/modules/engine/README.md).

---

## Event pipeline (data flow)

```
                           +----------------------+
   remoted / VD / Others ─►│   httpsrv (events)   │  UDS HTTP ingestion
                           +---------┬------------+
                                     │ JSON event
                                     ▼
                          +----------------------+
                          │  router/Orchestrator │  fan-out per active policy
                          +----------┬-----------+
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
        Policy A (std)         Policy B (custom)       Tester session
              │                      │                      │
              └──────────┬───────────┴──────────┬───────────┘
                         ▼                      ▼
        ┌────────────────────────────────────────────────┐
        │     bk::IController  (Rx; Taskflow alternative)│
        │                                                │
        │   pre-filter → decoders → pre-enrichment       │
        │             → enrichment (geo, ioc, kvdb)      │
        │             → post-filter → outputs            │
        └────────────────────┬───────────────────────────┘
                             │
                             ▼
              wazuh-indexer  /  file outputs (streamlog)
```

- One incoming event ⇒ one independent traversal **per active policy**.
- Inside a policy, decoders are arranged hierarchically (a root decoder dispatches to children), and decoders are grouped into **integrations**.
- The `builder` module compiles policy assets into an expression tree; the `bk` backend materializes that tree into a runnable pipeline. `main.cpp` always injects the Rx backend (`bk::rx::ControllerMaker`); the Taskflow backend is built and tested but not wired.

---

## Architectural layers

`source/` contains the modules. Below they are grouped by their role; arrows point in the direction of the dependency (a layer depends on the layers above it). Each entry links to that module's own README — the deep dive lives there, this index does not duplicate it.

### Foundation

Used by virtually every other module.

- [base/](base/README.md) — Shared primitives: logging (spdlog), JSON wrappers, error types (`base::Error`, `base::RespOrError`), expression trees (`base::Term`), the event type (`base::Event`), the manager configuration loader (`base::managerConfig`), process and time utilities.
- [proto/](proto/readme.md) — Protobuf (`*.proto`) schema for the API (the `eMessages` library). Wire format is JSON, but protobuf is the single source of truth shared by C++ handlers and the Python clients.
- [yml/](yml/) — yaml-cpp ↔ RapidJSON conversion used during config and content loading. No README.
- [conf/](conf/README.md) — Engine settings resolved per key as environment variable → `analysisd.*` key in `wazuh-manager-internal-options.conf` → default, with typed validation. Read in `main.cpp` and passed to modules as constructor arguments.
- [hlp/](hlp/README.md) — Type-specific parsers (IP, date, JSON, CSV, …). The parser library that decoders are built from.
- [parsec/](parsec/README.md) — Header-only parser-combinator library that underlies `logpar` and `logicexpr`.
- [logicexpr/](logicexpr/README.md) — Boolean expression parser/evaluator (Shunting-Yard) used in `check` stages.
- [logpar/](logpar/README.md) — Compiles declarative log-format strings into composed `hlp` parsers.
- [defs/](defs/README.md) — `$variable` substitution with cycle detection, used in asset definitions.
- [schemf/](schemf/README.md) — WCS schema and field-type validation (build-time and runtime).
- [fastqueue/](fastqueue/README.md) — Bounded thread-safe queues (lock-free `CQueue`, mutex `StdQueue`) with optional rate limiting.
- [fastmetrics/](fastmetrics/README.md) — Lock-free counters, gauges and pull callbacks in a process-wide registry, served by the `metrics` API handlers.
- [agentcache/](agentcache/) — Header-only TTL cache of agent metadata used by the `/events/enriched` ingestion handler (`agentcache::AgentMetadataCache`). No README; see [agentcache/include/agentcache/agentMetadataCache.hpp](agentcache/include/agentcache/agentMetadataCache.hpp).

### Storage

- [store/](store/README.md) — JSON document store with pluggable driver (`FileDriver` ships in tree). The engine's persistent KV.
- [cmstore/](cmstore/README.md) — Content repository: namespaces holding decoders, filters, outputs, integrations, KVDBs and policies, with bidirectional UUID↔name caches.
- [kvdbstore/](kvdbstore/README.md) — In-memory KVDB cache materialized from `cmstore` for decoder/filter lookups; entries expire when no handler holds them.
- [iockvdb/](iockvdb/README.md) — RocksDB-backed IOC database with RCU-style atomic hot-swap of the whole database instance.

### Compilation & execution backend

- [builder/](builder/) — The compilation hub. Reads assets from `cmstore` and produces executable `IPolicy` expression trees. `logpar`, `kvdbstore`, `iockvdb`, `geo`, `streamlog` and `wiconnector` reach it through the `BuilderDeps` struct; `cmstore`, `schemf`, `defs` and `store` are constructor arguments. No module README; the public interface is in [builder/include/builder/](builder/include/builder/), and the helper/stage builders are described in [builder/src/builders/README.md](builder/src/builders/README.md).
- [bk/](bk/README.md) — Two interchangeable execution backends (RxCpp observable graph or Taskflow DAG) for the compiled expression. Provides node-tracing and hot-reload.

### Enrichment & I/O services

- [geo/](geo/README.md) — MaxMind GeoIP/ASN lookups with hash-based hot-reload.
- [streamlog/](streamlog/README.md) — Async rotating log channels (size+time, gzip, retention) used by file outputs and `dumper`.
- [dumper/](dumper/README.md) — Toggleable raw-event dumper that writes via `streamlog` when active.
- [scheduler/](scheduler/README.md) — Priority thread-pool task scheduler for periodic syncs and metric flushes.
- [wiconnector/](wiconnector/README.md) — Thread-safe client for the Wazuh Indexer: events, policy resources, IOCs and remote config. Sole egress to the indexer.

### Synchronization & remote configuration

- [confremote/](confremote/README.md) — Pulls remote runtime configuration from the indexer with rollback on rejection.
- [cmcrud/](cmcrud/README.md) — Validation/adapter layer between the API and `cmstore` mutations; enforces canonical ordering and namespace import atomicity.
- [cmsync/](cmsync/README.md) — Periodic content sync from indexer; hot-swaps router routes when policies change.
- [iocsync/](iocsync/README.md) — Periodic IOC sync into `iockvdb` with atomic hot-swap.
- [rawevtindexer/](rawevtindexer/README.md) — Toggleable forensic indexing of raw (pre-processing) events.

### Routing & runtime

- [router/](router/README.md) — Production `Router` (worker pool) + synchronous `Tester` + `Orchestrator` façade. Owns event queues, policy `Environment`s, and route hot-swap.

### API gateway

- [httpsrv/](httpsrv/README.md) — UDS HTTP server (cpp-httplib). Two instances are created in `main`: the management API (`engine-api-http.sock`) and, when event processing is enabled, the event-ingestion server (`engine-ingest-http.sock`, route `POST /events/enriched`).
- [api/](api/README.md) — Per-domain handler factories: `router`, `tester`, `cmcrud`, `geo`, `ioccrud`, `dumper`, `rawevtindexer`, `metrics`, `status`, `event`. They translate JSON↔protobuf and delegate to the corresponding domain interface.

### Entry point

- [main.cpp](main.cpp) — Process entry. Signal/daemon handling, dependency-injection wiring, `StackExecutor` for LIFO shutdown.
- [stackExecutor.hpp](stackExecutor.hpp) — Records shutdown callbacks at construction order and runs them in reverse.

---

## Module dependency graph (high level)

`base`, `conf`, `proto` and other foundation libraries are omitted — they are used everywhere. An arrow `A ──► B` means *A links B* (the `target_link_libraries` lists in each module's `CMakeLists.txt`); `B ◄── A` is the same edge drawn from the other side. The graph emphasizes the runtime hubs.

```
      api (handlers per domain) ──► httpsrv, and the domain module each handler drives

      ┌──────────────┐    ┌─────────────────┐
      │   cmsync     │───►│     router      │───► fastqueue, bk, rawevtindexer, store
      └──────┬───────┘    │  (Orchestrator) │
             │            └────────┬────────┘
             │                     │
             ▼                     ▼
      ┌──────────────┐     ┌──────────────┐
      │   cmcrud     │────►│   builder    │ ─── compilation hub
      └──────┬───────┘     └──┬───┬───┬───┘
             │                │   │   │
             ▼                │   │   └────────────► geo, streamlog, defs
      ┌──────────────┐        │   │
      │   cmstore    │◄───────┘   └────► logpar ──► hlp, parsec
      └──────────────┘                   schemf
                                         kvdbstore ──► cmstore
                                         iockvdb ◄── iocsync

        ┌────────┐
        │ store  │◄── builder, router, cmsync, confremote, iocsync, iockvdb, geo, streamlog
        └────────┘

                  ┌────────────────┐
                  │  wiconnector   │ ──► wazuh-indexer    (sole egress)
                  └────────────────┘
                          ▲
              builder, cmsync, iocsync, confremote, rawevtindexer
```

Key relationships:

- **`router` is the runtime hub.** It owns event queues, worker threads and route lifecycle; `cmsync` hot-swaps its routes.
- **`builder` is the compilation hub.** Every dependency that contributes to event processing reaches it, through `BuilderDeps` or its constructor.
- **`store` and `cmstore` are the data hubs.** Persisted state (schemas, allowed fields, ruleset, sync state) flows through them.
- **`wiconnector` is the only egress to the indexer.** All outbound traffic to the indexer goes through it.

---

## Startup & dependency injection (`main.cpp`)

Modules are wired together in [main.cpp](main.cpp) using `std::shared_ptr` and a `StackExecutor` that records teardown callbacks for LIFO shutdown. Construction is staged so each phase only depends on phases above it. Some phases are gated by `conf::key::SERVER_ENABLE_EVENT_PROCESSING`.

1. **Process bootstrap** — option parsing (`-f` foreground, `-t` test configuration, `-d` debug, repeatable). In standalone mode `-t` exits 0 immediately and logging starts from environment variables (`logging::getStandaloneLoggingConfig()`). In manager mode the process `chdir`s to the home (`base::process::getWazuhHome()`), loads `/etc/wazuh-manager/wazuh-manager.conf` through `base::managerConfig::load()` (`-t` validates it with file checks instead and exits) and opens `logs/wazuh-manager.log`/`.json` through the manager log sink (`base/managerLogSink.hpp`). The soft `RLIMIT_NOFILE` is then raised to a fixed `8192` (never above the hard limit, never lowered if already higher), followed by `goDaemon()` unless `-f`.
2. **Configuration** — `conf::Conf` reads `wazuh-manager-internal-options.conf` from `/etc/wazuh-manager/` (never in standalone mode); `main.cpp` reads each setting with `confManager.get<T>(conf::key::…)` and passes the values to the module constructors. Then `SIGINT`/`SIGTERM` get a handler that sets the shutdown flag and `SIGPIPE` is ignored.
3. **Privilege drop** (manager-integrated mode only) — the process starts as `root` and switches group and user to the hardcoded `wazuh-manager:wazuh-manager` (`base::process::WAZUH_GROUP`/`WAZUH_USER`), unless disabled via `key::DROP_PRIVILEGES`; group first, since `setgid()` is not permitted after `setuid()`. Everything below runs unprivileged. In standalone mode the launcher's user/group are inherited untouched.
   Afterwards the log level is applied (`analysisd.debug` in manager mode, raised by `-d`) and, in manager mode, the PID file is created under `var/run/`.
   > **Caveat when debugging with `DROP_PRIVILEGES=false`:** running as `root` leaves every runtime-created path (`data/store`, `data/ruleset`, `data/kvdb-ioc`, `data/mmdb`, `data/tzdb`, the stream-log channels `logs/<channel>/<YYYY>/<MMM>/`, `var/run`) owned by `root:root`. Re-enabling the drop then fails at startup with a permission error from the first module that writes — `chown -R wazuh-manager:wazuh-manager` those paths before restarting. See [configuration.md](../../../docs/ref/modules/engine/configuration.md#process-privileges).
4. **Core data layer** — `store::Store` (with `FileDriver`) → `cmstore::CMStore` → `kvdbstore::KVDBManager` → `iockvdb::KVDBManager(store)` → `geo::Manager(store, downloader)` → `fastmetrics::registerManager()` → `schemf::Schema` (loads `schema/engine-schema/0` from `store`).
5. **Parsing** — `hlp::initTZDB(...)` then `logpar::Logpar` (uses `schema/wazuh-logpar-overrides/0` from `store` and the schema validator); `hlp::registerParsers(logpar)`.
6. **Scheduler & I/O** (always, but most consumers gated on `enableProcessing`) — `scheduler::Scheduler` (registered for early shutdown). When `enableProcessing` is on: `wiconnector::WIndexerConnector` (queue metrics registered as pull callbacks) and `streamlog::LogManager(store, scheduler)`.
7. **Compilation hub** — `builder::Builder(cmStore, schemaValidator, defs, allowedFields, builderDeps, store)` where `BuilderDeps` carries `logpar`, `kvdbManager`, `IOCkvdb`, `geoManager`, `streamLogger`, `indexerConnector` and the file-output rotation config. Then `cmcrud::CrudService(cmStore, builder)`.
8. **Background services** — `router::Orchestrator(...)` is always created, started immediately and registered for shutdown. Gated on `enableProcessing`: `confremote::ConfRemoteManager`, `rawevtindexer::RawEventIndexer` (its `index_raw_events` trigger registered on the remote-configuration manager), `cm::sync::CMSync`, `ioc::sync::IocSync` (scheduled as `ioc-sync-task` unless its interval is 0), `dumper::Dumper(streamLogger, …)` and the `remote-conf-sync` task. The `geo-sync-task` is scheduled regardless of the gate, unless its interval is 0.
9. **API surface** — the management `httpsrv::Server` is created, then per-domain handlers register their routes against it: metrics, geo, router, tester, dumper, rawevtindexer (only when it exists), cmcrud, ioccrud, status. Finally `apiServer->start()` on `analysisd.server_api_socket` (`engine-api-http.sock`). When `enableProcessing` is on, a second `httpsrv::Server` ("Event services") serves `POST /events/enriched` (`api::event::handlers::pushEvent`, with the `agentcache::AgentMetadataCache`) on `analysisd.server_enriched_events_socket` (`engine-ingest-http.sock`); then the `clean-agent-cache` and `cm-sync-task` tasks are scheduled and `scheduler->start()` runs. The main thread then waits for a shutdown signal. Socket defaults and every setting are listed in [configuration.md](../../../docs/ref/modules/engine/configuration.md).

Shutdown is the exact reverse: `StackExecutor` drains callbacks in LIFO. The event-ingestion server stops first, then the API server; the dumper is deactivated, the geo manager, `iocsync`, `cmsync`, the orchestrator and `confremote` are asked to shut down, `streamlog` and `wiconnector` (`requestShutdown()`, then `shutdown()`) follow, and the scheduler stops last; in standalone mode logging is torn down after it.

---

## Domain glossary

The engine uses a small but specific vocabulary, mirrored across the codebase, the API and the user manual.

- **Event** — JSON document representing a security log line, carrying agent/cluster metadata. The unit of work flowing through the engine.
- **Wazuh Common Schema (WCS)** — Authoritative typed field schema all output events must conform to. Owned by the indexer; the engine fetches `schema/engine-schema/0` from `store` at startup.
- **Resource / Asset** — Content units held by `cmstore` (`cm::store::ResourceType`: decoder, output, filter, integration, KVDB). Decoders, filters and outputs are *assets*, named `<type>/<name>/<version>` (e.g. `decoder/aws-cloudtrail/0`, `output/indexer/0`).
- **Decoder** — Asset that parses and normalizes events into WCS fields. Decoders are arranged hierarchically (root → children) and grouped into integrations.
- **Integration** — Ordered group of decoders + KVDBs that belong to one product or log source. Every decoder lives in exactly one integration.
- **Filter** — Boolean predicate over an event. Pre-filters drop events before decoding; post-filters drop events before they reach outputs.
- **Output** — Destination for processed events (Wazuh Indexer, file). Bundled with the manager, not synced from content.
- **Policy** — Named pipeline `pre-filter → decoders → pre-enrichment → enrichment → post-filter → outputs`. Multiple policies run concurrently.
- **Namespace / Space** — Logical content partition. Two spaces ship: **standard** (Wazuh-maintained) and **custom** (user). The indexer is the source of truth; the engine mirrors it locally.
- **KVDB** — Lightweight key-value store consulted by decoders/filters during processing. Regular KVDBs are per-space; IOC and Geo databases are global.
- **Helper** — Reusable function callable from decoder/filter stages: condition helpers (in `check`) and mapping helpers (in `map`).
- **Stage** — Operation block inside a decoder: `check` (boolean), `parse|<field>` (extraction), `normalize` (with nested `map`).
- **Route / Environment** — Runtime instance of a compiled policy held by the orchestrator. Routes can be hot-swapped without restart.

---

## Conventions

- **C++17** across the engine; `clang-format` and `clang-tidy` configured at `engine/`.
- Each module exposes its `I<Name>` interfaces in `interface/<module>/` (a separate `<module>::i<module>`-style CMake target), implementation headers in `include/<module>/`, sources in `src/`, GoogleTest tests in `test/src/` (unit tests in `test/src/unit/`), and mocks for other modules' tests in `test/mocks/`. Not every module has every piece (`conf`, `hlp`, `logpar`, `yml`, `agentcache` have no `interface/`).
- Dependencies are injected as `std::shared_ptr` and wired exclusively in [main.cpp](main.cpp); modules never instantiate their own dependencies.
- API handlers follow a factory pattern; see [api/README.md](api/README.md) for the contract.

---

## Further reading

- [User manual / quick-start](../../../docs/ref/modules/engine/README.md) — operator-facing documentation.
- [api/README.md](api/README.md) — API handler conventions.
- [router/README.md](router/README.md) — runtime orchestration, route lifecycle and tester semantics.
- [builder/](builder/) — policy compilation (no module README; start at [builder/include/builder/builder.hpp](builder/include/builder/builder.hpp) and [builder/src/builders/README.md](builder/src/builders/README.md)).
- [bk/README.md](bk/README.md) — execution backends.
