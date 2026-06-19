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
        │     bk::IController  (Rx or Taskflow)          │
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
- The `builder` module compiles policy assets into an expression tree; the `bk` backend materializes that tree into a runnable pipeline (Rx or Taskflow).

---

## Architectural layers

`source/` contains the modules. Below they are grouped by their role; arrows point in the direction of the dependency (a layer depends on the layers above it). Each entry links to that module's own README — the deep dive lives there, this index does not duplicate it.

### Foundation

Used by virtually every other module.

- [base/](base/) — Shared primitives: logging (spdlog), JSON wrappers, error types (`base::Error`, `RespOrError`), expression trees (`base::Term`, `base::Event`), process and time utilities. No README; see [base/include/base/](base/include/base/).
- [proto/](proto/) — Protobuf (`*.proto`) schema for the API. Wire format is JSON, but protobuf is the single source of truth shared by C++ handlers and the Python clients. No README; the `.proto` files in this directory are the contract.
- [yml/](yml/) — yaml-cpp ↔ RapidJSON conversion used during config and content loading.
- [conf/](conf/README.md) — Three-tier config (env → json file → defaults) with typed validation. Read by every module at startup.
- [hlp/](hlp/README.md) — Type-specific parsers (IP, date, JSON, CSV, …). The parser library that decoders are built from.
- [parsec/](parsec/README.md) — Header-only parser-combinator library that underlies `logpar` and `logicexpr`.
- [logicexpr/](logicexpr/README.md) — Boolean expression parser/evaluator (Shunting-Yard) used in `check` stages.
- [logpar/](logpar/README.md) — Compiles declarative log-format strings into composed `hlp` parsers.
- [defs/](defs/README.md) — `$variable` substitution with cycle detection, used in asset definitions.
- [schemf/](schemf/README.md) — WCS schema and field-type validation (build-time and runtime).
- [fastqueue/](fastqueue/README.md) — Bounded thread-safe queues (lock-free `CQueue`, mutex `StdQueue`) with optional rate limiting.
- [fastmetrics/](fastmetrics/README.md) — Lock-free counters/gauges/pull-callbacks with periodic JSON dump.

### Storage

- [store/](store/README.md) — JSON document store with pluggable driver (`FileDriver` ships in tree). The engine's persistent KV.
- [cmstore/](cmstore/README.md) — Content repository: namespaces holding decoders, filters, outputs, integrations, KVDBs and policies, with bidirectional UUID↔name caches.
- [kvdbstore/](kvdbstore/README.md) — In-memory KVDB cache materialized from `cmstore` for decoder/filter lookups; entries expire when no handler holds them.
- [iockvdb/](iockvdb/README.md) — RocksDB-backed IOC database with RCU-style atomic hot-swap of the whole database instance.

### Compilation & execution backend

- [builder/](builder/) — The compilation hub. Reads assets from `cmstore` and produces executable `IPolicy` expression trees, pulling in `logpar`, `schemf`, `kvdbstore`, `iockvdb`, `geo`, `streamlog` and `wiconnector` via a `BuilderDeps` struct. No README; the public interface is in [builder/include/builder/](builder/include/builder/).
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

- [httpsrv/](httpsrv/README.md) — UDS HTTP server (cpp-httplib). Two instances are created in `main`: the management API and the optional remote-event-receiver.
- [api/](api/README.md) — Per-domain handler factories: `router`, `tester`, `cmcrud`, `geo`, `ioccrud`, `dumper`, `rawevtindexer`, `metrics`, `event`. They translate JSON↔protobuf and delegate to the corresponding domain interface.

### Entry point

- [main.cpp](main.cpp) — Process entry. Signal/daemon handling, dependency-injection wiring, `StackExecutor` for LIFO shutdown.
- [stackExecutor.hpp](stackExecutor.hpp) — Records shutdown callbacks at construction order and runs them in reverse.

---

## Module dependency graph (high level)

`base`, `conf`, `proto` and other foundation libraries are omitted — they are used everywhere. The graph emphasizes the runtime hubs.

```
                                  ┌──────────────┐
                                  │     api      │   (handlers per domain)
                                  └──────┬───────┘
                                         │
                                  ┌──────▼───────┐
                                  │   httpsrv    │
                                  └──────────────┘

      ┌──────────────┐    ┌─────────────────┐    ┌──────────────┐
      │   cmsync     │───►│     router      │◄───│  fastqueue   │
      └──────┬───────┘    │  (Orchestrator) │    └──────────────┘
             │            └────────┬────────┘
             │                     │
             ▼                     ▼
      ┌──────────────┐     ┌──────────────┐
      │   cmcrud     │     │   builder    │ ─── compilation hub
      └──────┬───────┘     └──┬───┬───┬───┘
             │                │   │   │
             ▼                │   │   └────────────► geo, streamlog
      ┌──────────────┐        │   │
      │   cmstore    │◄───────┘   └────► logpar ──► hlp ──► parsec
      └──────┬───────┘                   schemf
             │                           kvdbstore
             ▼                           iockvdb ◄── iocsync
        ┌────────┐
        │ store  │◄── confremote, rawevtindexer
        └────────┘

                  ┌────────────────┐
                  │  wiconnector   │ ──► wazuh-indexer    (sole egress)
                  └────────────────┘
                          ▲
              cmsync, iocsync, confremote,
              rawevtindexer, streamlog, builder
```

Key relationships:

- **`router` is the runtime hub.** It owns event queues, worker threads and route lifecycle; `cmsync` hot-swaps its routes.
- **`builder` is the compilation hub.** Every dependency that contributes to event processing is funneled into it via `BuilderDeps`.
- **`store` and `cmstore` are the data hubs.** Persisted state (schemas, decoder unmodifiable fields, ruleset, sync state) flows through them.
- **`wiconnector` is the only egress to the indexer.** All outbound traffic to OpenSearch goes through it.

---

## Startup & dependency injection (`main.cpp`)

Modules are wired together in [main.cpp](main.cpp) using `std::shared_ptr` and a `StackExecutor` that records teardown callbacks for LIFO shutdown. Construction is staged so each phase only depends on phases above it. Some phases are gated by `conf::key::SERVER_ENABLE_EVENT_PROCESSING`.

1. **Process bootstrap** — option parsing, logging (standalone vs `libwazuhshared`), signal handlers (`SIGINT`, `SIGTERM`, `SIGPIPE` → ignore), optional `goDaemon()`.
2. **Configuration** — `conf::Conf` loads from ini file; every later module reads it via `confManager.get<T>(key::…)`.
3. **Core data layer** — `store::Store` (with `FileDriver`) → `cmstore::CMStore` → `kvdbstore::KVDBManager` → `iockvdb::KVDBManager(store)` → `geo::Manager(store, downloader)` → `fastmetrics::registerManager()` → `schemf::Schema` (loads `schema/engine-schema/0` from `store`).
4. **Parsing** — `hlp::initTZDB(...)` then `logpar::Logpar` (uses `schema/wazuh-logpar-overrides/0` from `store` and the schema validator); `hlp::registerParsers(logpar)`.
5. **Scheduler & I/O** (always, but most consumers gated on `enableProcessing`) — `scheduler::Scheduler` (registered for early shutdown). When `enableProcessing` is on: `wiconnector::WIndexerConnector` (queue metrics registered as pull callbacks) and `streamlog::LogManager(store, scheduler)`.
6. **Compilation hub** — `builder::Builder(cmStore, schemaValidator, defs, decoderUnmodifiableFields, builderDeps, store)` where `BuilderDeps` carries `logpar`, `kvdbManager`, `IOCkvdb`, `geoManager`, `streamLogger`, `indexerConnector` and the file-output rotation config. Then `cmcrud::CrudService(cmStore, builder)`.
7. **Background services** (gated) — `confremote::ConfRemoteManager`, `rawevtindexer::RawEventIndexer`, `router::Orchestrator(...)` (started immediately and registered for shutdown), `cmsync::CMSync`, `iocsync::IocSync` (scheduled via `scheduler`), `dumper::Dumper(streamLogger)`.
8. **API surface** — `httpsrv::Server` is created, then per-domain handlers register their routes against it: metrics, geo, router, tester, dumper, rawevtindexer, cmcrud, ioccrud. Finally `apiServer->start(socketPath)`. An optional second `httpsrv::Server` is created for the remote-event-receiver (event ingestion).

Shutdown is the exact reverse: `StackExecutor` drains callbacks in LIFO. The API server stops first (it joins client connections), background services request shutdown and join, the orchestrator drains queues, `streamlog` and `wiconnector` flush, the scheduler stops, and logging is the last thing torn down.

---

## Domain glossary

The engine uses a small but specific vocabulary, mirrored across the codebase, the API and the user manual.

- **Event** — JSON document representing a security log line, carrying agent/cluster metadata. The unit of work flowing through the engine.
- **Wazuh Common Schema (WCS)** — Authoritative typed field schema all output events must conform to. Owned by the indexer; the engine fetches `schema/engine-schema/0` from `store` at startup.
- **Asset** — Smallest content unit (decoder, filter, output, integration, KVDB, schema). Addressed as `<type>/<name>/<version>` (e.g. `decoder/aws-cloudtrail/0`).
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
- Each module exposes an `I<Module>` interface in `include/<module>/`, implementations in `src/`, GoogleTest unit tests in `test/src/unit/`, and mocks for use by other modules' tests in `test/mocks/`.
- Dependencies are injected as `std::shared_ptr` and wired exclusively in [main.cpp](main.cpp); modules never instantiate their own dependencies.
- API handlers follow a factory pattern; see [api/README.md](api/README.md) for the contract.

---

## Further reading

- [User manual / quick-start](../../../docs/ref/modules/engine/README.md) — operator-facing documentation.
- [api/README.md](api/README.md) — API handler conventions.
- [router/README.md](router/README.md) — runtime orchestration, route lifecycle and tester semantics.
- [builder/](builder/) — policy compilation (no README; start at [builder/include/builder/builder.hpp](builder/include/builder/builder.hpp)).
- [bk/README.md](bk/README.md) — execution backends.
