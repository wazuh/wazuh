# remoted module (C++ worker bridge)

A self-contained C++17 module that `remoted` launches in its own thread, receiving a
configuration struct to initialize itself. It mirrors the pattern `modulesd` uses for
`inventory_sync` / `vulnerability_scanner`, but integrates via **direct link** (like
`router`) instead of `dlopen`, and passes configuration as a **typed C struct** instead of
a serialized `cJSON`.

This is the isolation boundary between remoted's C code and C++: everything under this
directory is C++, and the only file remoted's C sources include is
[`include/remoted_module.h`](include/remoted_module.h).

## Layout

```
remoted_module/
├── include/                        # public surface (the only C↔C++ contact)
│   ├── remoted_module.h            # C-ABI: config struct + start/stop
│   └── remotedModule.hpp           # public C++ Singleton facade
├── src/
│   ├── remotedModule.cpp           # extern "C" shims + facade delegation + log sink definition
│   ├── remotedModuleFacade.hpp     # worker thread + lifecycle; owns the HTTP server + auth + endpoints
│   ├── auth/                       # ns remoted::auth — framework-agnostic AES-CMAC auth (see below)
│   ├── http_server/                # ns remoted::http — transport-agnostic HTTP(S) sub-layer (see below)
│   └── endpoints/                  # ns remoted::endpoints — endpoint contract + auth gateway (see below)
└── test/unit/                      # GoogleTest tests (C-ABI black-box + HTTP server + auth + gateway)
```

Each internal concern is a folder under `src/` (namespaced, PRIVATE, reachable by prefix —
`"auth/...`", `"http_server/...`", `"endpoints/...`" — since `src/` is on the include path). New
endpoints get their own folder under `src/endpoints/<name>/`.

## HTTP(S) server sub-layer (`src/http_server/`)

Transport only. The module exposes an HTTPS endpoint behind a **transport-agnostic interface** so
the underlying library (today RESTinio, likely `Boost.Beast + Boost.Asio` later) can be swapped
without touching any registered endpoint.

```
src/http_server/
├── IHttpServer.hpp          # neutral interface + types (Method/HttpRequest/HttpResponse/
│                            #   IHttpResponder/HttpServerConfig). No transport types leak here.
├── httpServerConfig.hpp/.cpp# buildHttpServerConfig(): C-ABI struct -> HttpServerConfig (+ fallbacks)
├── httpServerFactory.hpp    # makeHttpServer() -> the single transport swap point
└── RestinioHttpServer.hpp/.cpp # RESTinio + OpenSSL implementation (PImpl hides RESTinio in the .cpp)
```

- **Endpoint registration:** `addRoute(Method, path, handler)` before `start()`.
- **Async handlers (non-blocking I/O threads):** a raw handler is
  `void(const HttpRequest&, std::shared_ptr<IHttpResponder>)`. Each request is dispatched to a
  bounded worker pool with a **deferred response**, so RESTinio's I/O threads never block on
  slow handler work (disk, calls to other APIs). A handler may respond inline or capture the
  responder, offload the blocking work, and call `responder->send(...)` later from any thread.
- **Configuration** (via the C-ABI struct, each with env/default fallback when empty/0):
  `port`, `certificate_path`, `private_key_path`, `io_threads`, `http_worker_threads`.
  Environment overrides: `WAZUH_REMOTED_HTTPS_{ADDRESS,PORT,IO_THREADS,WORKER_THREADS,
  MAX_BODY_SIZE,CERTIFICATE,PRIVATE_KEY}`.
- **Swapping the library:** implement a new `IHttpServer` and return it from `makeHttpServer()`;
  nothing else changes.

## Endpoints (`src/endpoints/`)

Ties the transport and the auth layer together and defines the endpoint contract; future endpoints
each get a folder here.

```
src/endpoints/
├── endpoint.hpp             # shared contract: type aliases (Method/HttpResponse/IHttpResponder/
│                            #   AuthenticatedRequest) + the async AuthenticatedHandler typedef
└── authGateway.hpp/.cpp     # runs the auth middleware, then hands the verified request + responder
                             #   to the endpoint handler
```

- **Endpoint handler (async):**
  `using AuthenticatedHandler = std::function<void(const remoted::auth::AuthenticatedRequest&, std::shared_ptr<IHttpResponder>)>;`
  It runs on the worker pool after auth succeeds and **owns delivering the response** — inline or
  later (async), by calling `responder->send(...)` exactly once.
- **`AuthGateway`** owns one `AuthMiddleware` and exposes
  `addAuthenticatedRoute(IHttpServer&, Method, path, AuthenticatedHandler)`. It registers a raw
  async route whose worker-thread body runs the full validation (`beginSession → update → finish`,
  always synchronous — AES-CMAC over CPU, off the I/O threads), maps any `AuthError` through
  `publicErrorFor()` to the client status/message on failure, and on success calls the handler with
  the verified `AuthenticatedRequest` and the responder. The facade registers a **dummy
  `POST /stateless`** this way: it validates the request (auth only) and answers `200` **without**
  parsing the H/E payload or ingesting anything; `400`/`401`/`413` come straight from the gateway.

## Agent<->manager auth middleware (`src/auth/`)

Framework-agnostic implementation of the agent<->manager request authentication protocol:
canonical request construction, incremental AES-CMAC, timestamp window and constant-time
comparison. `authTypes.hpp` holds the shared contract (`AuthenticatedRequest`/`AuthError`/
`publicErrorFor`/`AuthConfig`) and `iAgentKeystore.hpp` the key-lookup interface; `authMiddleware`,
`cmac`, `keystore` are the implementation. It knows nothing about RESTinio or sockets
-- the `AuthGateway` (in `endpoints/`) is the only adapter between it and our transport. Depends on
OpenSSL (linked into `remoted_module`).

Unit tests under `test/unit/` (`cmac_test.cpp`, `authMiddleware_test.cpp`,
`keystore_test.cpp`); `authMiddleware_test.cpp` exercises `AuthMiddleware` against a
scratch `client.keys` file it writes to `/tmp`, through `Keystore` -- there is no
in-memory stand-in.

**Agent key lookup:** `Keystore` reads `etc/client.keys` directly and parses it
the same way the manager's own `OS_ReadKeys()` does (id/name/ip/key columns, `#`/`!`-marked removed
entries skipped), independent of remoted's C `keystore`. This was a deliberate choice over reaching
into remoted's live `keystore`: remoted loads it in `W_ENCRYPTION_KEY` mode (see `secure.c`), which
never keeps the raw pre-shared key in memory -- only a derived key for the legacy message cipher --
so the raw key needed for signing has to come from the file itself. The key column is treated as
lowercase hex and hex-decoded as-is (no further derivation); it must decode to 16, 24 or 32 bytes to
work as an AES-CMAC key. client.keys has no "disabled but present" state -- a removed entry is simply
absent -- so `AuthError` has no separate inactive-agent case; an unknown and a removed agent are
indistinguishable and both resolve to `AuthError::UnknownAgent`.

## Contract

```c
void remoted_module_start(full_log_fnc_t callbackLog, const remoted_module_config_t* configuration);
void remoted_module_stop(void);
```

- `start()` launches the worker thread and returns immediately; the module owns the thread.
- `stop()` signals the worker (atomic flag + condition_variable) and joins it. Safe to call
  when never started.
- All exceptions are caught at the `extern "C"` boundary — nothing throws into C.
- Logging is routed back into remoted's `ossec.log` via the `full_log_fnc_t` callback
  (remoted passes `mtLoggingFunctionsWrapper`) and the `LOGFN_*` macros.

## Integration in remoted

- Build wiring: `add_subdirectory(remoted_module)` + `remoted_module` added to
  `target_link_libraries(remoted_lib ...)` in `src/remoted/CMakeLists.txt`.
- Lifecycle: `HandleSecure()` (in `src/remoted/src/secure.c`) builds a
  `remoted_module_config_t`, calls `remoted_module_start(...)`, and registers
  `remoted_module_stop` with `atexit`.

## Tests

Built when `UNIT_TEST` is enabled:

```bash
ctest --test-dir <build> -R remoted_module_utest -V
```
