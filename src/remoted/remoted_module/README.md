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
├── include/
│   ├── remoted_module.h            # C-ABI: config struct + start/stop (the only C↔C++ contact)
│   ├── remotedModule.hpp           # public C++ Singleton facade
│   ├── cmac.hpp                    # incremental AES-CMAC wrapper (auth middleware)
│   ├── clientKeysFileResolver.hpp  # IAgentKeyResolver over a direct read of client.keys
│   └── authMiddleware.hpp          # auth middleware public API
├── interface/                      # framework-agnostic auth contract
│   ├── authTypes.hpp               # AuthenticatedRequest / AuthError / publicErrorFor / AuthConfig
│   └── iAgentKeyResolver.hpp       # agent id -> pre-shared AES key
├── src/
│   ├── remotedModule.cpp           # extern "C" shims + facade delegation + log sink definition
│   ├── remotedModuleFacade.hpp     # worker thread + lifecycle; owns the HTTP server + auth layer
│   ├── cmac.cpp                    # incremental AES-CMAC over OpenSSL's EVP_MAC
│   ├── authMiddleware.cpp          # canonical-request + timestamp-window + MAC verification
│   ├── clientKeysFileResolver.cpp  # client.keys parsing + in-memory lookup
│   └── http_server/                # transport-agnostic HTTP(S) sub-layer + auth gateway (see below)
└── test/unit/                      # GoogleTest tests (C-ABI black-box + HTTP server + auth middleware)
```

To grow the module, add sub-libraries under `src/<submodule>/` each with their own
`CMakeLists.txt` (the `vulnerability_scanner` pattern) and link them into `remoted_module`.

## HTTP(S) server sub-layer (`src/http_server/`)

The module exposes an HTTPS endpoint behind a **transport-agnostic interface** so the
underlying library (today RESTinio, likely `Boost.Beast + Boost.Asio` later) can be swapped
without touching any registered endpoint.

```
src/http_server/
├── IHttpServer.hpp          # neutral interface + types (Method/HttpRequest/HttpResponse/
│                            #   IHttpResponder/HttpServerConfig). No transport types leak here.
├── httpServerConfig.hpp/.cpp# buildHttpServerConfig(): C-ABI struct -> HttpServerConfig (+ fallbacks)
├── httpServerFactory.hpp    # makeHttpServer() -> the single transport swap point
├── authGateway.hpp/.cpp     # runs the auth middleware, then calls a post-auth endpoint handler
└── RestinioHttpServer.hpp/.cpp # RESTinio + OpenSSL implementation (PImpl hides RESTinio in the .cpp)
```

- **Endpoint registration:** `addRoute(Method, path, handler)` before `start()`. The facade
  registers a dummy `GET /` returning `{"status":"ok","module":"remoted"}`.
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

### Auth gateway (`src/http_server/authGateway.*`)

Header/auth validation is common to (almost) every endpoint and is always **synchronous** (it is
AES-CMAC over CPU, not I/O), so it is centralized here instead of repeated per endpoint.
`AuthGateway` owns an `AuthMiddleware` (below) and exposes:

```cpp
using AuthenticatedHandler = std::function<HttpResponse(const wazuh_auth::AuthenticatedRequest&)>;
void addAuthenticatedRoute(IHttpServer&, Method, const std::string& path, AuthenticatedHandler);
```

It registers a raw async route on the server whose worker-thread body runs the full validation
(`beginSession → update → finish`), maps any `AuthError` through `publicErrorFor()` to the
client-visible status/message, and only on success calls the endpoint handler with the verified
`AuthenticatedRequest`. Because our transport already dispatches to the worker pool, this
synchronous validation never blocks the I/O threads. The facade registers a **dummy
`POST /stateless`** this way: it validates the request (auth only) and returns `200` **without**
parsing the H/E payload or ingesting anything; `400`/`401`/`413` come straight from the gateway.

### Agent<->manager auth middleware

Framework-agnostic implementation of the agent<->manager request authentication protocol:
canonical request construction, incremental AES-CMAC, timestamp window and constant-time
comparison. `interface/` holds the contract (`AuthenticatedRequest`/`AuthError`/`AuthConfig` and
the `IAgentKeyResolver`); `include/` + `src/` hold the implementation (`AuthMiddleware`, `Cmac`,
`ClientKeysFileResolver`). It knows nothing about RESTinio or sockets -- the `AuthGateway` above is
the only adapter between it and our transport. Depends on OpenSSL (linked into `remoted_module`).

Unit tests under `test/unit/` (`cmac_test.cpp`, `authMiddleware_test.cpp`,
`clientKeysFileResolver_test.cpp`); `authMiddleware_test.cpp` exercises `AuthMiddleware` against a
scratch `client.keys` file it writes to `/tmp`, through `ClientKeysFileResolver` -- there is no
in-memory stand-in resolver.

**Agent key resolution:** `ClientKeysFileResolver` reads `etc/client.keys` directly and parses it
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
