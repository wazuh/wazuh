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

**Scope today: scaffolding plus a live UDS server with a stub route.** There is no FlatBuffer
decoding, no indexer connector and no agent session handling yet — `POST /inventory/sync` accepts a
request, counts its bytes and **discards** it. The point is to have the module installed, registered,
logging and *serving real connections*, so the rest can be built on top of something verifiable.

## Layout

```
inventory_sync_server/
├── CMakeLists.txt                       # SHARED lib; test/ gated behind if(UNIT_TEST)
├── include/                             # the ONLY C<->C++ contact surface
│   ├── inventory_sync_server.h          # C-ABI: POD config struct + start/stop + fn-ptr typedefs
│   └── inventorySyncServer.hpp          # public C++ Singleton facade (EXPORTED)
├── src/
│   ├── inventorySyncServer.cpp          # extern "C" shims + the DSO's Log::GLOBAL_LOG_FUNCTION
│   ├── inventorySyncServerFacade.hpp    # internal engine: worker thread, lifecycle, retry
│   ├── common/
│   │   └── logThrottle.hpp              # per-condition log rate limiter (decides, never logs)
│   ├── endpoints/
│   │   └── syncEndpoint.{hpp,cpp}       # POST /inventory/sync policy (a stub today)
│   └── http_server/
│       ├── IUdsHttpServer.hpp           # neutral interface + the PEER CONTRACT comment
│       ├── udsHttpServerConfig.{hpp,cpp}# C-ABI struct -> UdsHttpServerConfig, every default
│       ├── udsHttpServerFactory.hpp     # makeUdsHttpServer() -- the single transport swap point
│       ├── requestParser.{hpp,cpp}      # llhttp wrapper + the limits llhttp does not have
│       ├── inFlightBudget.hpp           # byte budget + RAII reservation
│       └── asioUdsHttpServer.{hpp,cpp}  # asio + llhttp implementation (PImpl)
├── test/
│   ├── CMakeLists.txt                   # builds inventory_sync_server_utest
│   └── unit/                            # 103 tests
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
  handler, so it never blocks on I/O.
- **Exceptions never cross into C.** Both shims catch `std::exception` *and* `...` — a non-standard
  exception escaping into modulesd's C code would be `std::terminate`, taking the whole daemon down.
- modulesd resolves both symbols with `dlopen`/`dlsym`, so the function-pointer typedefs at the
  bottom of the header are load-bearing rather than a convenience.

**A typed struct, not a JSON blob.** `inventory_sync` takes a `const cJSON*`; this takes a POD struct
with fixed-size buffers, so there is no parse step and no key name that can be silently misspelled.
Every numeric field follows one sentinel rule: **`<= 0` (or an empty string) means "the caller has no
opinion, use the module default"**. modulesd fills them from `getDefine_Int_default(...)` with a `0`
fallback precisely so each default lives in exactly one place — this module.

**The one exception is `indexer`**, which is `const cJSON*`. The indexer connector consumes nested
JSON with arrays (`hosts[]`, `ssl.certificate_authorities[]`, …), which a fixed-size C struct cannot
express without flattening it on one side and re-nesting it on the other. Passing the subtree through
untouched also keeps this header from having to track the connector's schema at all.

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
  cannot deadlock. Note the phase-2 gap where the ingestion pipeline's shutdown will go: it has to
  happen *between* the transport's two phases, so its in-flight responders are still deliverable.
- `run()` is an exception barrier that deliberately does **not** re-enter the loop: an exception that
  repeats every iteration would spin forever writing to `wazuh-manager.log`, which is worse than a
  dead worker.
- A failed server start escalates: the first attempt is an **ERROR** naming both the path and the
  setting to change, the next hour of retries stays at debug, then one WARN per hour.
- `stop()` runs from modulesd's signal handler, which calls **every** module's `stop()` sequentially
  before joining them under one shared 30 s budget. That is why the transport's drain window is 2 s
  by default: a long drain here delays every other module's teardown.

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

Anything else is 404; a known path with the wrong verb is 405 with an `Allow` header.

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

`inventory_sync_server_utest` — 103 tests.

| File | What it covers |
|---|---|
| `requestParser_test.cpp` | The parser, with no sockets or threads. `ParsesPeerRequestSplitAtEveryOffset` is the highest-value one: it feeds the peer's exact bytes split at every offset, which covers header continuation across a read boundary, a request line cut mid-token, a body straddling two reads — and pins the resume-offset arithmetic at every alignment. Also the golden peer bytes, lower-casing, raw query retention, 411/413/414/431, malformed input, and the llhttp `on_headers_complete` return-value trap. |
| `udsHttpServerConfig_test.cpp` | Every documented default from a zeroed struct, positive overrides, negative-means-default, and that the default socket path stays **relative** (a regression there silently breaks the chroot/chdir agreement). |
| `syncEndpoint_test.cpp` | Route policy with a capturing responder, no socket. Pins the provisional path/verb and that the handler does not retain the payload. |
| `inFlightBudget_test.cpp`, `logThrottle_test.cpp` | Accounting and rate-limiting, including under concurrency. |
| `udsHttpServer_test.cpp` | The live server over a real UDS. Highlights: `DeferredReplyFromAnotherThreadArrivesAfterTheHandlerReturned` (the reason this design exists) and **`ThreeHundredConcurrentDeferralsOnTwoIoThreads`** — the requirement stated so it can fail, and the test a blocking thread-per-request server cannot pass. Plus socket mode under a hostile umask, stale-socket recovery, the non-socket refusal, budget/connection 503s, the 500-on-throw barrier *and that the reactor still serves afterwards*, and both never-answered backstops. |
| `udsShutdown_test.cpp` | The shutdown protocol: S1, S2, S3 (including after the server is destroyed), the bounded drain, force-close, concurrent `send()`/`stop()` from 64 threads, and the whole protocol under 200 live deferrals. |
| `inventorySyncServerModule_test.cpp` | The C-ABI as a black box, through the real `start()`/`stop()`. Includes the `m_running` wedge regression, the escalating ERROR naming the path and the setting, and the indexer borrow contract. |

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

## Deliberately absent

Named so none of it is mistaken for an oversight:

- FlatBuffer decoding of the sync protocol, and the agent session table (`agentSession`, `gapSet`,
  `inventorySyncQueryBuilder` in the older module).
- The indexer connector. Its configuration already arrives and is validated at startup — the module
  logs the shape it received (counts and set/unset only, never values) so a misconfigured `<indexer>`
  shows up as `hosts=0` now rather than on the day the connector is wired up.
- The RocksDB store. Its path constant is already reserved (`queue/inventory-sync-server`) because
  choosing it wrongly is destructive, not merely broken.
- Removing the router subscription from `inventory_sync`, and deleting that module.
- remoted's side: the HTTPS endpoint, the downstream socket path, and the per-endpoint response
  timeout it will need for an ingestion path that can defer for minutes.
