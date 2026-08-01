# inventory_sync_server (transitional C++ module)

A self-contained C++ module that `wazuh-manager-modulesd` launches **alongside** the existing
`inventory_sync`, exposing the inventory synchronization ingress over an **HTTP/1.1 Unix domain
socket** instead of the router.

Today `inventory_sync` receives agent inventory through the router's observer pattern: `remoted`
publishes to the `inventory-states` topic and the module subscribes to it, with replies going back
out over a *different* channel (the active-response datagram socket). Replacing that with a direct
UDS conversation is too large a change to graft onto the existing module, so this one is built next
to it. When it is complete, `inventory_sync` is removed and this becomes the only inventory sync
module.

**Scope today: a live UDS server, gated on real indexer connectors, serving four routes of which the
ingestion one is still a stub.** There is no FlatBuffer decoding or agent session handling yet —
`POST /inventory/sync` accepts a request, counts its bytes and **discards** it. The module DOES already construct a real
shared `IndexerSession` plus **both** an `IndexerConnectorSync` and an `IndexerConnectorAsync`, and
will not start accepting UDS connections unless all three construct successfully (see
[Indexer connectors](#indexer-connectors-srcindexer) below). The point is to have the module
installed, registered, logging, gatekeeping on its real dependencies, and *serving real connections*,
so the rest can be built on top of something verifiable.

## Layout

```
inventory_sync_server/
├── CMakeLists.txt                       # SHARED lib; test/ gated behind if(UNIT_TEST)
├── include/                             # the ONLY C<->C++ contact surface
│   ├── inventory_sync_server.h          # C-ABI: POD config struct + start/stop + fn-ptr typedefs
│   ├── inventorySyncServer.hpp          # public C++ Singleton facade (EXPORTED)
│   └── inventorySyncServerTestHooks.hpp # TEST-ONLY exported hooks (see Tests)
├── src/
│   ├── inventorySyncServer.cpp          # extern "C" shims + the DSO's Log::GLOBAL_LOG_FUNCTION
│   ├── inventorySyncServerFacade.hpp    # internal engine: worker thread, lifecycle, retry
│   ├── inventorySyncServerTestHooks.cpp # TEST-ONLY hook implementations (see Tests)
│   ├── common/
│   │   ├── logThrottle.hpp              # per-condition log rate limiter (decides, never logs)
│   │   └── clusterIdentity.hpp          # ClusterIdentity + buildClusterIdentity() from the C-ABI config
│   ├── endpoints/
│   │   ├── syncEndpoint.{hpp,cpp}       # POST /inventory/sync policy (a stub today)
│   │   ├── statsEndpoint.{hpp,cpp}      # POST /stats policy (dummy: enrich + echo + discard)
│   │   └── configEndpoint.{hpp,cpp}     # POST /config policy (dummy, duplicate of stats on purpose)
│   ├── indexer/
│   │   ├── IIndexerSession.hpp          # seam over the shared session (construction IS the contract)
│   │   ├── IIndexerConnectorSync.hpp    # seam, isAvailable() only -- deliberately NOT a shared base
│   │   ├── IIndexerConnectorAsync.hpp   # seam: isAvailable() + the two fire-and-forget writes
│   │   ├── indexerSessionAdapter.hpp    # wraps the real IndexerSession
│   │   ├── indexerConnectorSyncAdapter.hpp   # wraps IndexerConnectorSync, built on the session
│   │   ├── indexerConnectorAsyncAdapter.hpp  # wraps IndexerConnectorAsync, built on the session
│   │   └── indexerConnectorConfig.{hpp,cpp}  # TWO C-ABI overlays, one per connector's key names
│   └── http_server/
│       ├── IUdsHttpServer.hpp           # neutral interface + the PEER CONTRACT comment
│       ├── udsHttpServerConfig.{hpp,cpp}# C-ABI struct -> UdsHttpServerConfig, every default
│       ├── udsHttpServerFactory.hpp     # makeUdsHttpServer() -- the single transport swap point
│       ├── requestParser.{hpp,cpp}      # llhttp wrapper + the limits llhttp does not have
│       ├── inFlightBudget.hpp           # byte budget + RAII reservation
│       └── asioUdsHttpServer.{hpp,cpp}  # asio + llhttp implementation (PImpl)
├── test/
│   ├── CMakeLists.txt                   # builds inventory_sync_server_utest
│   └── unit/                            # 196 tests
└── tools/
    └── send_sync.py                     # stdlib-only manual sender over the UDS
```

Each internal concern is a folder under `src/` (namespaced, PRIVATE, reachable by prefix:
`http_server/...`, `endpoints/...`, `common/...`). New endpoints get their own unit under
`src/endpoints/`.

## Coexistence with `inventory_sync`

Both modules run in the **same** `wazuh-manager-modulesd` process while the migration is in flight.
This is the section that matters operationally: everything here fails in production rather than in
the tests.

| Resource | `inventory_sync` | `inventory_sync_server` | Why they must differ |
|---|---|---|---|
| RocksDB store | `queue/inventory_sync` | `queue/inventory-sync-server` *(reserved, unused)* | the older module does a recursive **remove** of its own path at startup, and `queue/inventory_sync_server` would be matched by an `inventory_sync*` glob — the hyphenated form is unambiguously outside it |
| Router | subscribes to `inventory-states` | **does not use the router at all** | the router's remote-subscriber map is keyed by **topic**, not by subscriber id, so a second subscriber to that topic in one process throws `Subscriber already exist`. `inventory_sync` is registered first, so the throw would land here, be swallowed at the `extern "C"` boundary, and leave this module silently dead |
| UDS socket | `queue/sockets/keystore` | `queue/sockets/inventory-sync.sock` | one bind per path |
| Log tag | `…:inventory-sync` | `…:inventory-sync-server` | an operator has to tell the two apart in `wazuh-manager.log` |
| `Log::GLOBAL_LOG_FUNCTION` | its own copy | its own copy | hidden visibility, one definition per DSO — required, not optional |
| C++ symbols | global namespace | `invsync::` + `InventorySyncServer` | default-visibility symbols **interpose** across DSOs in one process, so the public class must not be named `InventorySync` |

**Registration order is load-bearing.** The `wm_add()` call goes *after* `inventory_sync`'s in
`wm_config()`: `wm_add()` appends and `main()` starts the modules in list order, so the older module
still claims its socket and its router subscription first.

**Socket path.** Relative (`queue/sockets/inventory-sync.sock`), because modulesd `chdir()`s to the
install directory and remoted `chroot()`s into it — a relative path is the only form both resolve to
the same file. Named for the *service* rather than for this transitional module, so remoted's
downstream configuration is written once and does not have to change again when this module replaces
`inventory_sync`.

**Socket permissions.** modulesd runs as root with its effective group set to the wazuh group, so the
socket is created owned by that group; `chmod 0660` after `bind()` is what lets remoted connect. The
`chmod` is mandatory rather than defensive: `bind()` applies the umask, so the mode it leaves behind
is whatever the daemon's umask allows.

## C-ABI ([include/inventory_sync_server.h](include/inventory_sync_server.h))

```c
EXPORTED void inventory_sync_server_start(full_log_fnc_t callbackLog,
                                          const inventory_sync_server_config_t* configuration);
EXPORTED void inventory_sync_server_stop(void);
```

- **start()** launches the worker thread and returns immediately; the module owns the thread. Safe
  with a `NULL` configuration (every default applies).
- **stop()** signals and joins. Safe if never started, and idempotent. It runs from modulesd's signal
  handler, so every wait it performs is BOUNDED and named -- but it does block: it joins the worker,
  which may be inside the indexer session's synchronous per-host health checks, and it drains the
  transport. With several unreachable indexer hosts this has been measured in the tens of seconds, which
  is why every one of those waits has a ceiling and why they are sized to fit the daemon's shutdown
  budget together.
- **Exceptions never cross into C.** Both shims catch `std::exception` *and* `...` — a non-standard
  exception escaping into modulesd's C code would be `std::terminate`, taking the whole daemon down.
- modulesd resolves both symbols with `dlopen`/`dlsym`, so the function-pointer typedefs at the
  bottom of the header are load-bearing rather than a convenience.

**A typed struct, not a JSON blob.** `inventory_sync` takes a `const cJSON*`; this takes a POD struct
with fixed-size buffers, so there is no parse step and no key name that can be silently misspelled.
Every numeric field follows one sentinel rule: **`<= 0` (or an empty string) means "the caller has no
opinion, use the module default"**. modulesd fills them from `getDefine_Int_default(...)` with a `0`
fallback precisely so each transport default lives in exactly one place — this module.

Two documented exceptions, both on the field itself in the header:

- **The nine indexer fields** carry real defaults from modulesd, not the `0` sentinel, because the
  default belongs to the shared Indexer Connector rather than to this module. modulesd mirrors the
  library's values so an out-of-range setting is rejected at configuration time. They are therefore
  duplicated across the `.so` boundary, and nothing pins the two copies together.
- **`max_inflight_bytes`** treats a NEGATIVE value as "unlimited", because `0` is a real setting for it
  (the documented off switch) and had to be distinguishable from an absent option. modulesd makes that
  distinction and translates, so `0` still means "no opinion" across the ABI.

**The one exception is `indexer`**, which is `const cJSON*`. The indexer connector consumes nested
JSON with arrays (`hosts[]`, `ssl.certificate_authorities[]`, …), which a fixed-size C struct cannot
express without flattening it on one side and re-nesting it on the other. Passing the subtree through
untouched also keeps this header from having to track the connector's schema at all.
The `indexer_sync_*`/`indexer_async_*` fields (plain `int`/`long long`, same sentinel rule) are
overlaid onto a *copy* of that subtree before construction, once per connector — see
[Indexer connectors](#indexer-connectors-srcindexer).

`indexer_async_max_queue_bytes` is the **one field that does not follow the sentinel rule**: `0` there
is the connector's own documented "unlimited", not "use the module default". modulesd therefore ships
a real bounded default (64 MiB) for it, and the option's minimum is `0` rather than `1` — with `min=1`,
an operator writing the legal value `0` would hit `getDefine_Int_default()`'s `merror_exit()` and take
modulesd down.

Its ownership contract: **borrowed for the duration of the `start()` call only.** The `extern "C"`
shim deep-copies it into an owned `nlohmann::json` and then clears the pointer defensively, so the
caller may free it as soon as `start()` returns. `wm_inventory_sync_server.c` duplicates
`indexer_config` and deletes the duplicate right after the call, and a test pins the contract by
freeing the tree while the module is still running (meaningful under ASan).

## Lifecycle

- The UDS server is **not** started from `start()` — it is started from the worker loop, so `start()`
  stays fast and non-throwing even when the socket path is not yet usable, and a failed start retries
  every 60 s for free.
- `m_running` is set only **after** the `std::thread` exists. Setting it first would mean a throwing
  thread constructor leaves the facade claiming to run with no worker, and every later `start()` is
  then refused as "already started" — permanently wedged, doing nothing.
- `stop()` tears down in order and **joins outside the lifecycle lock**, so a concurrent `start()`
  cannot deadlock. Phase 2 tears down the three indexer objects, between the transport's two phases --
  which is where the ingestion pipeline's own shutdown will go too, so its in-flight responders stay
  deliverable.
- `run()` is an exception barrier that deliberately does **not** re-enter the loop: an exception that
  repeats every iteration would spin forever writing to `wazuh-manager.log`, which is worse than a
  dead worker.
- A failed *indexer* start escalates: the first attempt is an **ERROR** naming the stage that is
  blocking and what to check, the next hour of retries stays at debug, then one WARN per hour. A socket
  path that could never be bound is not retried at all -- it is validated up front and reported as
  fatal, because nothing an operator does at runtime fixes it.
- `stop()` runs from modulesd's signal handler, which calls **every** module's `stop()` sequentially
  before joining them under one shared 30 s budget. That is why the transport's drain window is 2 s
  by default: a long drain here delays every other module's teardown.

## Indexer connectors (`src/indexer/`)

The module builds **three** things, in order: one shared `IndexerSession`, then an
`IndexerConnectorSync` and an `IndexerConnectorAsync` on top of it.

**Why both connectors.** `IndexerConnectorSync` is the class `inventory_sync` already uses, and this
module's whole purpose is to replace it — so it needs the same config keys and the same richer
write/lock API (`bulkIndex`, `bulkDelete`, `scopeLock`, `flush`, `registerNotify`) the ported sync
pipeline will need. `IndexerConnectorAsync` is the high-throughput, fire-and-forget write path for
functionality still to come. They are not interchangeable, which is the whole reason their
configuration is kept rigorously separate (below).

**Why a shared session.** Each connector's constructor would otherwise run its own synchronous
`GET /_cat/health` per configured host (5 s timeout each), its own keystore read and its own CA merge,
and start its own monitoring thread. Two connectors would double all of it. `IndexerSession` — added
to `shared_modules/indexer_connector` for this — does that work **once** and both connectors adopt it,
so adding the async connector costs no extra startup latency, no second monitoring thread and no
second `queue/keystore` open. The component test
`TwoConnectorsSharingASessionCostOneHealthCheckRound` pins it, with
`SessionlessConnectorsEachRunTheirOwnHealthCheckRound` as the contrast that keeps it honest.

### The startup gate

**The UDS server will not start accepting connections unless all three construct successfully.** All
four stages share the one retry/escalation mechanism, in `tryStartHttpServer()`:

- **The gate is "did construction throw", not "is the indexer reachable".** The constructors validate
  configuration synchronously — hosts present, any referenced CA file exists on disk,
  `max_retry_delay_seconds` sane — and throw `IndexerConnectorException` on failure. A host that is
  merely *unreachable* does **not** throw; it only stays unavailable until the monitor sees it come up.
  So the indexer is free to start *after* modulesd: a valid `<indexer>` block pointing at a down
  indexer still opens the socket. Only a genuinely invalid configuration blocks it.
- **Each of the three is constructed at most once per `start()`/`stop()` cycle, and memoised
  independently.** A successful construction is a "configuration is valid" signal that cannot change
  without a restart. `buildAndPublish()` publishes each one *the moment it succeeds* rather than at the
  end of the attempt — otherwise a persistently failing later stage would discard the earlier ones and
  rebuild them next heartbeat, which for the session means another full round of health checks every
  60 s. `TheSucceedingSlotsAreNotRebuiltWhileAnotherRetries` pins this; it caught exactly that bug.
- **`reportFailedStart()` names the failing stage in every branch**, not just the first-attempt ERROR.
  With four stages the failing one can *alternate* between heartbeats while the ERROR is emitted only
  once per incident, so without the label an hour of debug lines cannot say which part is stuck. Each
  stage also names its own option family, so an operator is never pointed at the wrong knob.
- **Construction runs outside `m_lifecycleMutex`** (phase B of three). Holding it across the health
  checks would queue `stop()` — which runs from modulesd's signal handler under a 30 s budget shared by
  every module — behind them. Note the honest limit: `stop()` joins the worker, so this does not by
  itself shorten the wait when the worker is already inside a constructor; what it does is let `stop()`
  set `m_stopping` immediately, which is what lets phase B bail early. Combined with the shared
  session, the worst case stays at **one** health-check round.
- **Teardown is unconditional and reverse-ordered** (async, sync, session). The gate can legitimately
  leave only some of them built, and each carries live background threads from construction, so gating
  one reset on another's pointer would leak those threads on every `stop()` in that state.
  `StopTearsDownWhatExistsEvenWhenLaterStagesNeverRan` pins it.

### Configuration: two families that must not be crossed

`IndexerConnectorSync` reads `max_bulk_size`; `IndexerConnectorAsync` reads `bulk_max_bytes` — **the
same concept under a different key name**. Handing either connector the other's key is **ignored
silently**: no throw, no log, the built-in default applies instead. Three things guard against that:

1. **Two separate option families**, `inventory_sync_server_indexer_sync_*` and
   `..._indexer_async_*`, mapped to C fields named `indexer_<sync|async>_<the connector's own key
   name>` — so crossing them produces a visible name mismatch rather than a silent no-op.
2. **Two separate builders**, `buildSyncConnectorConfig()`/`buildAsyncConnectorConfig()`, each
   emitting *only* the keys its own connector reads. Unit tests assert each result does **not** contain
   the other's key names.
3. **One funnelled setter** for every numeric write. `max_queue_bytes` is the only key the connector
   gates on `is_number_unsigned()` (every other uses `is_number_integer()`), so a *signed* JSON integer
   there is silently ignored and the queue stays unbounded. `setIfPositive()` is the only way
   `indexerConnectorConfig.cpp` writes a number, and it always stores `std::size_t`.
   `AsyncMaxQueueBytesIsStoredAsAnUnsignedJsonNumber` pins the type, not just the key's presence.

The nine options, all prefixed `wazuh_modules.inventory_sync_server_`:

| Option | Connector key | min | max | default |
|---|---|---|---|---|
| `indexer_sync_max_bulk_size` | `max_bulk_size` | 4096 | 100 MiB | 10 MiB |
| `indexer_sync_flush_interval_seconds` | `flush_interval_seconds` | 1 | 3600 | 20 |
| `indexer_sync_max_retry_delay_seconds` | `max_retry_delay_seconds` | 1 | 3600 | 15 |
| `indexer_async_bulk_max_bytes` | `bulk_max_bytes` | 4096 | 100 MiB | 4 MiB |
| `indexer_async_flush_interval_seconds` | `flush_interval_seconds` | 1 | 3600 | 20 |
| `indexer_async_max_retry_delay_seconds` | `max_retry_delay_seconds` | 1 | 3600 | 15 |
| `indexer_async_max_queue_bytes` | `max_queue_bytes` | 0 | 2147483647 | 64 MiB |
| `indexer_async_logger_queue_size` | `logger_queue_size` | 1 | 65536 | 8 |
| `indexer_async_logger_threads` | `logger_threads` | 1 | 64 | 1 |

`flush_interval_seconds` is the one key name both read; it is fed from two independent fields so the
two can be tuned separately.

The minimum of **1** on both `max_retry_delay_seconds` exists because the connector constructors reject
anything below their base retry delay of 1. Note what that means in combination with the `<=0` sentinel:
a rejecting value is **not reachable from configuration** — `0` would be dropped by `setIfPositive()`
and the connector's own default of 15 would apply, and the option's minimum makes an operator's `0` a
startup-time complaint rather than a silent fallback. So in practice the only stage a *configuration*
mistake can fail is the session (shared `hosts`/`ssl.*`); the per-connector stages guard against
non-config failures such as thread-spawn or allocation failure, and their gating is covered by the unit
tests' injected failures rather than by any reachable configuration.

Each object also gets its own log tag (`:indexer`, `:sync`, `:async`), so their own output can be told
apart. The `:suffix` form is load-bearing — `LogFn::compose()` truncates from the first `(`, so a
parenthesised suffix would be discarded.

## Transport (`src/http_server/`)

A hand-rolled asynchronous HTTP/1.1-over-UDS server on standalone Asio + llhttp, reachable only
through `makeUdsHttpServer()` — the single swap point. Neither asio nor llhttp appears in any header,
so both stay PRIVATE link dependencies.

- Responses here are deferred for as long as an indexer round-trip takes, with hundreds in flight, 
  so **a pending request must cost a socket plus a queue entry, not a thread.**
- **No handler thread pool.** Handlers run inline on their connection's strand, because their job is
  to hand the payload to the pipeline and return. This makes the "not a thread" property literally
  true and removes an entire shutdown-drain phase. The cost is that a blocking handler stalls one I/O
  thread, which is why `RouteHandler` documents **MUST NOT BLOCK** as a contract.
- **Admission control runs at headers-complete**, before a body byte is read: route lookup (404/405),
  the declared `Content-Length` against the body cap (413), then the in-flight byte budget (503).
  Reserving from the *declared* length is what makes `maxInFlightBytes` bound the **read-phase peak**
  as well as resident payloads — remoted's server reserves only once the body is already buffered, so
  there the read phase needs a separate `maxParallelConnections * maxBodySize` bound; here one number
  covers both.
- **Both caps reject explicitly**, never queue silently: over the byte budget or the connection cap
  the peer gets a 503 it can classify, not a stalled or reset socket.
- **The parser stops at the head.** llhttp reserves non-zero returns from `on_headers_complete` for
  "no body" and "upgrade", so the rejection decision cannot be signalled that way; it pauses instead
  and the verdict travels out separately. Without the pause, a request small enough to arrive in one
  read would be fully buffered before admission control ever got a say.
- **The limits are hand-written** (`maxUrlSize`, `maxHeaderNameSize`, `maxHeaderValueSize`,
  `maxHeaderCount`, `maxBodySize`) because llhttp has none of its own — remoted gets these free from
  RESTinio.
- **Chunked bodies are refused with 411.** With no declared length there is nothing to reserve, so
  one connection could consume the whole budget. Detected from the header rather than an llhttp flag
  enum, which keeps it version-proof.
- **Socket lifecycle:** unlink a *stale socket* before bind (otherwise an unclean shutdown wedges the
  module with `EADDRINUSE` forever), but **refuse to unlink a path that exists and is not a socket** —
  a typo in the configured path must not delete an operator's file. `chmod` after bind. Unlink on
  stop, so restart is idempotent from both sides.
- **Interop caveat, deliberate:** a rejection decided at the head closes the connection, so a peer
  still writing a *large* rejected body sees a transport failure instead of the status. Draining the
  remainder would mean reading everything the client declared, bounded only by a deadline it controls.
  remoted caps the body on its own inbound side and answers the agent 413 there, so this only arises
  when this module's cap is set *below* remoted's — a misconfiguration worth fixing rather than
  absorbing. See the INTEROP NOTE in `asioUdsHttpServer.cpp`.

### Two-phase shutdown

The riskiest part, so the invariants are stated rather than implied:

| | Invariant |
|---|---|
| **I1** | Sessions and responders declare `shared_ptr<Runtime>` **first**, so it is destroyed **last**: `~socket` and `~steady_timer` always run while the `io_context` is alive |
| **I2** | **No asio I/O object is ever destroyed from inside `~io_context()`** |
| **S1** | after `stopAccepting()`: no handler will be invoked again, and every dispatch that started has returned |
| **S2** | after `stopAccepting()`: the I/O runtime is still **running**, so a deferred reply still reaches the wire |
| **S3** | after `stop()` — and after the server is destroyed — `send()` from any thread is a well-defined **no-op** |

S3 is stronger than remoted's equivalent, which declares that case undefined; it holds because
responders co-own the I/O runtime. I2 is not paranoia: the obvious teardown (`stop()` then join)
leaves queued handlers un-invoked, and `~io_context()` destroys them *before* shutting down its
services — so the last `shared_ptr<Session>` can drop, destroying a socket and a timer, while the
reactor is being torn down around them. remoted tolerates that because its sessions last
milliseconds and are few; ours last minutes and there are hundreds.

**A responder that is never used has three backstops**, in order of speed: dropping it unsent is
detected by its destructor (immediate 503, logged as the handler bug it is); retaining it forever hits
the response-phase timer (504); and shutdown force-closes whatever is left after the drain window.

## Routes

| Method | Path | Status | Body | Notes |
|---|---|---|---|---|
| GET | `/` | 200 | `{"status":"ok","module":"inventory_sync_server"}` | liveness probe; **exempt from the byte budget** so it keeps answering under memory pressure |
| POST | `/inventory/sync` | 202 | `{"status":"accepted"}` | **STUB — accepts and DISCARDS the payload.** The path is **PROVISIONAL**: it must match the target remoted's downstream configuration will point at, which lands separately. `syncEndpoint_test.cpp` pins it so a silent drift fails. |
| POST | `/stats` | 200 / 400 / 503 | the request document, enriched | **DUMMY** — reached through remoted's authenticated `POST /stats`. Requires `X-Wazuh-Agent-Id`. Echoes the document back with `wazuh.agent.id`, `wazuh.cluster.name`, `wazuh.cluster.node` and `@timestamp` added, then **discards** it. 400 on a missing/empty agent-id header, malformed JSON, or a body that is not a JSON *object*; **503 when no indexer host is healthy** (or the module is shutting down). |
| POST | `/config` | 200 / 400 / 503 | the request document, enriched | **DUMMY** — identical behaviour to `/stats`, deliberately implemented as a separate unit. |

Anything else is 404; a known path with the wrong verb is 405 with an `Allow` header.

### `/stats` and `/config` (dummies)

Both take a JSON object from an agent, stamp two fields onto it, echo it back, and drop it. Nothing is
indexed or stored. The pieces worth knowing:

- **The agent id comes from the `X-Wazuh-Agent-Id` header, never from the document.** remoted sets it
  from the identity it verified by AES-CMAC. Taking it from the body would make the enrichment
  worthless as an identity — a document claiming `"999"` cannot override the authenticated `"001"`, and
  a test pins exactly that. A request without the header did not come through remoted's authenticated
  route, so it is a contract violation rather than agent input, and answers 400.
- **`@timestamp` is `Utils::getCurrentISO8601()`** (`shared_modules/utils/timeHelper.h`), i.e.
  `YYYY-MM-DDTHH:MM:SS.mmmZ`. A pre-existing `@timestamp` in the document is overwritten: the server's
  clock is the authoritative one. The tests pin the shape, not just the presence.
- **Both stamps are written with JSON pointers** (`"/wazuh/agent/id"_json_pointer`), so the paths read
  the way they are spelled everywhere else in the schema.
- **Parsing is non-throwing** (`nlohmann::json::parse(..., allow_exceptions=false)`): a malformed
  document is ordinary input here, not an error condition, so it must not cost an exception per request.
  Serialization back out is still wrapped, because `dump()` can fail on input `parse()` accepted (e.g. a
  string holding invalid UTF-8).
- **They take the async indexer connector, and gate on it.** `makeHandler()` receives a
  `std::weak_ptr<IIndexerConnectorAsync>`; a valid document is answered **503** when the connector is
  gone (the module is stopping) or when `isAvailable()` is false (no configured host is healthy). The
  two share the 503 body — the caller's advice is "retry later" either way, and distinguishing them
  would leak internal state — but log differently: a throttled DEBUG1 for the shutdown case, a
  throttled **WARN** for the outage, since that one is operator-actionable.
- **The gate runs AFTER every 400.** A malformed document is the caller's fault and does not depend on
  the indexer, so it stays a 400 during an outage. With the checks reversed, an agent sending a bad
  payload would get a 503 and retry forever something that can never work. Both endpoint test suites
  and the e2e pin this ordering.
- **The connector is held weakly, and that is load-bearing.** Handler closures are stored in the
  transport's route table, which is co-owned by every outstanding responder — so a strong capture would
  stop `stop()`'s phase-2 `reset()` from actually destroying the connector, moving its destructor (and
  its background threads) to phase 3 or later, onto whatever thread released the last responder. A weak
  hold keeps the documented teardown ordering true, and stays correct once these handlers start
  deferring their replies. `IndexerGatingTest.StopTearsDownEverythingInReverseOrder` plus two
  per-endpoint tests fail if it is ever made strong (verified by mutation).
- **Nothing is indexed yet.** The dependency is injected and gated on, but neither `index()` nor
  `indexDataStream()` is called — a `NothingIsIndexedYet` test per endpoint pins that, so the day real
  processing lands it has to be updated deliberately.
- **The cluster name and node name are injected too, the same way as the indexer connector: at
  registration time, via `makeHandler()`'s `cluster` parameter** (`common/clusterIdentity.hpp`'s
  `ClusterIdentity`, built once per attempt by `buildClusterIdentity()` from
  `inventory_sync_server_config_t::cluster_name`/`node_name`). Unlike the connector there is no
  background object to protect, so it is captured **by value** — two small strings, cheap to copy,
  nothing to leak. Stamped at `/wazuh/cluster/name` and `/wazuh/cluster/node`, and like the agent id,
  the module's own configured identity overrides anything the document already claims there. An
  unconfigured cluster/node is stamped as an explicit empty string, not omitted — the C-ABI struct
  documents an empty buffer as "no opinion", not "leave this field out".
- They are **deliberate near-duplicates** rather than one handler registered on two paths — same
  reasoning as on the remoted side. Their real payloads will diverge; keep them in sync until then.

## Integration in modulesd

- **C shim:** `wazuh_modules/src/wm_inventory_sync_server.{c,h}` — the `wm_context`, the `dlopen`/
  `dlsym` resolution, the config build from `getDefine_Int_default(...)` + `get_cluster_name()` /
  `get_node_name()` + `indexer_config`, and `wm_inventory_sync_server_read()`. Picked up automatically
  by the C glob, so it needs no CMake edit of its own.
- **Registration:** one `#include` in `wazuh_modules/include/wmodules.h` and one `wm_add()` in
  `wm_config()` — after `inventory_sync`, before the database module. There is no `ossec.conf`
  plumbing: like `inventory_sync`, this module is added unconditionally on the manager.
- **Build:** three edits in `wazuh_modules/CMakeLists.txt` — the `include/` path (so the C shim finds
  the header), `add_subdirectory(...)` in the server-only branch, and the target in
  `wazuh_modulesd_lib`'s PUBLIC link list.
- **Install:** a block in `init/inst-functions.sh` for `libinventory_sync_server.so`, and an entry in
  `packages/rpms/SPECS/wazuh-manager.spec` — the RPM build fails on an unpackaged file. Debian does
  not enumerate `.so` files, so there is no deb change.
- **cJSON** comes from `wazuhext` (which bundles it whole-archive) rather than from a static
  `ext_cjson`, so this `.so` does not carry a second copy alongside the one modulesd already has.

## Tests

`inventory_sync_server_utest` — 201 tests.

| File | What it covers |
|---|---|
| `requestParser_test.cpp` | The parser, with no sockets or threads. `ParsesPeerRequestSplitAtEveryOffset` is the highest-value one: it feeds the peer's exact bytes split at every offset, which covers header continuation across a read boundary, a request line cut mid-token, a body straddling two reads — and pins the resume-offset arithmetic at every alignment. Also the golden peer bytes, lower-casing, raw query retention, 411/413/414/431, malformed input, and the llhttp `on_headers_complete` return-value trap. |
| `udsHttpServerConfig_test.cpp` | Every documented default from a zeroed struct, positive overrides, negative-means-default, and that the default socket path stays **relative** (a regression there silently breaks the chroot/chdir agreement). |
| `syncEndpoint_test.cpp` | Route policy with a capturing responder, no socket. Pins the provisional path/verb and that the handler does not retain the payload. |
| `statsEndpoint_test.cpp`, `configEndpoint_test.cpp` | The two dummies, one file each mirroring their duplicated implementations. Pin the path/verb (a wire contract with remoted, which lives in another binary), the lower-cased agent-id header name, that the enrichment lands at the documented JSON pointers, the ISO8601 timestamp *shape*, and the overrides that make the enrichment trustworthy: **the authenticated agent id** and **the injected cluster identity** both beat whatever the document already claims there, and a pre-existing `@timestamp` is replaced. Plus the 400 paths (non-object bodies, malformed JSON, missing/empty header), null-request tolerance, no payload retention, and that an unconfigured cluster identity is stamped as explicit empty strings rather than omitted. Also the injected async connector: **503 when it is unavailable or already gone**, that the 400s still win over an outage (the check ordering), that nothing is indexed yet, and that the handler does **not** keep the connector alive after returning — the last one is what makes a strong capture a test failure instead of a silent shutdown-ordering change. |
| `clusterIdentity_test.cpp` | `buildClusterIdentity()` in isolation: both buffers read, both empty stay empty, and one field set does not leak into the other. |
| `inFlightBudget_test.cpp`, `logThrottle_test.cpp` | Accounting and rate-limiting, including under concurrency. |
| `udsHttpServer_test.cpp` | The live server over a real UDS. Highlights: `DeferredReplyFromAnotherThreadArrivesAfterTheHandlerReturned` (the reason this design exists) and **`ThreeHundredConcurrentDeferralsOnTwoIoThreads`** — the requirement stated so it can fail, and the test a blocking thread-per-request server cannot pass. Plus socket mode under a hostile umask, stale-socket recovery, the non-socket refusal, budget/connection 503s, the 500-on-throw barrier *and that the reactor still serves afterwards*, and both never-answered backstops. |
| `udsShutdown_test.cpp` | The shutdown protocol: S1, S2, S3 (including after the server is destroyed), the bounded drain, force-close, concurrent `send()`/`stop()` from 64 threads, and the whole protocol under 200 live deferrals. |
| `serverDiagnostics_test.cpp` | The transport's observability contract: a throwing handler answers 500 and its ERROR is throttled across requests; limit rejections (413) and unknown routes (404) each leave a throttled trace; a peer that closes during a deferral frees its connection slot promptly instead of pinning it until the response timeout. |
| `inventorySyncServerModule_test.cpp` | The C-ABI as a black box, through the real `start()`/`stop()`. Includes the `m_running` wedge regression, the escalating ERROR naming the path and the setting, and the indexer borrow contract. |
| `indexerGating_test.cpp` | The four-stage startup gate. A real, unconfigured `IndexerSession` blocks the socket fast (no network needed — the hosts-missing check runs first, so it does not even open `queue/keystore`). Each of the three stages is failed in isolation to pin that the ERROR names *that* stage and that no later stage is attempted; that a healthy session + sync connector is **not** enough; that each slot is built exactly once across retries, and that the ones which already succeeded are not rebuilt while another keeps failing; that one heartbeat produces exactly one reported attempt (the escalation clock); and that `stop()` tears down in reverse order — including when only some stages ever ran. |
| `indexerConnectorConfig_test.cpp` | Pure unit tests of the two overlays, no server. Each builder emits only its own connector's key names and **not** the other's; `max_queue_bytes` is stored as an *unsigned* JSON number (the silent-ignore trap — a `contains()` assertion passes even with the bug); every overlaid key is unsigned; the two `flush_interval_seconds` are independent; negatives do not wrap to `SIZE_MAX`; `hosts`/`ssl.*` pass through and the input is not mutated. |

**Why some tests inject fakes.** The real `IndexerSession` constructor does synchronous network I/O (a
health check per configured host, 5 s timeout each) — unacceptable in a fast unit suite. Three
independent factory setters swap in test doubles, so a test can fail exactly one stage while leaving
the others healthy.

Calling those setters (or `forceRetryForTests()`) directly from a test `.cpp` would fail to link,
though: the facade is header-only, and its methods call `LOGFN_*` macros that need
`Log::GLOBAL_LOG_FUNCTION` — a hidden-visibility symbol only this module's own `.so` can resolve.
`include/inventorySyncServerTestHooks.hpp` + `src/inventorySyncServerTestHooks.cpp` route every hook
through plain `EXPORTED` functions defined in a `.cpp` (compiled into the `.so`, exactly like the
`extern "C"` `inventory_sync_server_start()`/`_stop()` shims), so calling them from the test binary is
a normal resolved symbol rather than an inline re-instantiation.

`test/unit/testIndexerConnectorFakes.hpp` wraps these into `installAlwaysAvailableFakeIndexers()` and
the per-stage failure variants, all returning one shared `ConnectorEvents` record — a single record
rather than three counters because independent counters cannot express the *relative* teardown order
`stop()` now specifies. `test/unit/testLogRecorder.hpp` holds the log-observing `LogRecorder`,
**shared across every test file in this binary** — `Log::assignLogFunction()` only assigns while empty,
so whichever file's `inventory_sync_server_start()` call happens first in the whole process wins for
good; a per-file recorder would leave every other file blind.

> The singular `installAlwaysAvailableFakeIndexer()`/`resetIndexerConnectorFactoryToProduction()` were
> **deleted rather than kept as aliases** when the second connector landed. Had the old names survived,
> every existing call site would have kept compiling while silently letting the *real* session and async
> connector be constructed — real `queue/keystore` opens and real per-host health checks — turning fast
> unit tests into slow, environment-dependent ones. Deleting the names made the migration a compile
> error at each call site instead.

**`m_failedStartAttempts` is reset in `start()`.** A stale count carried over from a previous
`start()`/`stop()` cycle would desync `reportFailedStart()`'s "first attempt" ERROR branch from what
is actually the first failure this time — found by running the suite with `--gtest_shuffle` across
several seeds (a test that deliberately drives multiple failed attempts landed, in some orderings,
before another test asserting on its own *first*-attempt wording).

```bash
ctest --test-dir src/build -R inventory_sync_server_utest -V
# or directly, with a filter:
src/build/wazuh_modules/inventory_sync_server/test/inventory_sync_server_utest \
  --gtest_filter='RequestParserTest.*'
```

**Several shutdown tests are only real regression checks under a sanitizer.** Without
`-DFSANITIZE=ON` a broken teardown *order* — an asio object destroyed while the reactor is being torn
down, or a responder touching a freed session — usually still passes. Run `udsShutdown_test.cpp`
under ASan and TSan before trusting a change to the shutdown protocol.

### Manual / end-to-end ([tools/send_sync.py](tools/send_sync.py))

Standard library only, so it runs on the manager's embedded interpreter. Run it from the manager's
home directory so the relative socket path resolves.

```bash
python3 tools/send_sync.py --health              # -> 200
python3 tools/send_sync.py --size 1024           # -> 202
python3 tools/send_sync.py --bad-route           # -> 404
python3 tools/send_sync.py --method PUT          # -> 405 with Allow
python3 tools/send_sync.py --size 4096 --repeat 200   # -> 200 x 202, and ONE throttled log line
```

`curl` works too:

```bash
curl -i --unix-socket queue/sockets/inventory-sync.sock http://localhost/
curl -i --unix-socket queue/sockets/inventory-sync.sock -X POST \
     -H 'Content-Type: application/octet-stream' --data-binary @/tmp/payload.bin \
     http://localhost/inventory/sync
```

## Operational notes

How this module's failure modes surface on the remoted side, and where to look first. Every
per-request failure condition on this side keeps one **throttled** log line (90 s window; the first
occurrence always emits), so the absence of a line means the absence of the condition.

- **Rejections can reach remoted as transport errors, not statuses.** The downstream client writes
  the whole request before reading any response, and this server rejects-and-closes at
  headers-complete. A rejection whose request body is still in flight (more than the socket buffer,
  ~200 KiB) surfaces in remoted as `transport_error` rather than as the status code — the throttled
  WARN on this side (`exceeding a configured limit`, `no route for ...`) is the authoritative
  record. remoted additionally logs 404/405 answers as a route contract mismatch.
- **Shutdown order is not coordinated.** `wazuh-server.sh stop` signals modulesd before remoted, so
  during a normal manager shutdown remoted may log connect failures and `protocol_error` lines for
  deferrals this server force-closed at the end of its short drain window. Expected during a
  shutdown; a problem only outside one.
- **A misconfigured `<indexer>` keeps the socket closed.** The startup gate builds the session and
  both connectors before opening the socket, so while any of them fails remoted sees connect
  failures even though modulesd is running — this side's gate log (ERROR on the first attempt, WARN
  hourly) is the one that names the setting to fix. An *unreachable* but well-configured indexer
  does NOT keep the socket closed, and the worker's heartbeat logs its availability transitions.
- **Timeouts are not cross-validated.** remoted's downstream response deadline (5 s default) must
  stay below this server's `response_timeout` (300 s default — a leak backstop, not a deadline).
  Nothing detects the two crossing; the peer-gone watch bounds the damage, releasing an abandoned
  deferral's connection as soon as the peer closes.
- **Backpressure is remoted's.** Its deferred-work limiter (256 slots shared by `/stateless`,
  `/stats` and `/config`) saturates long before this server's connection cap or byte budget, so
  under overload agents see remoted's 503 — and a slow engine can shed `/stats`/`/config` traffic,
  and vice versa. No layer retries or emits `Retry-After`; the agent's own policy is the only retry.

## Deliberately absent

Named so none of it is mistaken for an oversight:

- FlatBuffer decoding of the sync protocol, and the agent session table (`agentSession`, `gapSet`,
  `inventorySyncQueryBuilder` in the older module). Both indexer connectors exist and gate startup,
  but nothing in the request path calls into them yet — `POST /inventory/sync` still discards its
  payload without touching either connector at all. Only `isAvailable()` is forwarded through the
  seams; the write APIs (`bulkIndex`/`index`/…) are reached through the adapters' inner objects when
  the pipeline lands.
- The RocksDB store. Its path constant is already reserved (`queue/inventory-sync-server`) because
  choosing it wrongly is destructive, not merely broken.
- Removing the router subscription from `inventory_sync`, and deleting that module.
- remoted's side of `/inventory/sync`. Its HTTPS endpoint, downstream socket path and per-endpoint
  response timeout already exist and are used for `/stats` and `/config`; what is still missing is a
  downstream target for the ingestion route, and the longer response timeout an ingestion path that can
  defer for minutes will need.
