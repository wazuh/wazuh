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
│   ├── authMiddleware.hpp          # auth middleware public API
│   └── authServer.hpp              # IAuthServer implementation, shape/lifecycle only for now
├── interface/                      # contract any HTTP transport (Beast, RESTinio, ...) must satisfy
│   ├── authTypes.hpp
│   ├── iAgentKeyResolver.hpp
│   ├── iAuthServer.hpp
│   └── serverConfig.hpp
├── src/
│   ├── remotedModule.cpp           # extern "C" shims + facade delegation + log sink definition
│   ├── remotedModuleFacade.hpp     # worker std::thread + cooperative-shutdown lifecycle
│   ├── cmac.cpp                    # incremental AES-CMAC over OpenSSL's EVP_MAC
│   ├── authMiddleware.cpp          # canonical-request + timestamp-window + MAC verification
│   ├── clientKeysFileResolver.cpp  # client.keys parsing + in-memory lookup
│   └── authServer.cpp              # pimpl'd Impl: config/resolver/routes storage + running flag
└── test/unit/                      # GoogleTest black-box tests over the C-ABI + auth middleware
```

To grow the module, add sub-libraries under `src/<submodule>/` each with their own
`CMakeLists.txt` (the `vulnerability_scanner` pattern) and link them into `remoted_module`.

### Agent<->manager auth middleware

Framework-agnostic implementation of the agent<->manager request authentication
protocol: canonical request construction, incremental AES-CMAC, timestamp window
and constant-time comparison. `interface/` is the contract a concrete HTTP
transport must satisfy to use it; `include/` + `src/` hold this implementation.
Only depends on OpenSSL (linked straight into `remoted_module`, see `CMakeLists.txt`).

Not yet included: any Boost.Beast (or other library-specific) transport
implementation. Unit tests live under `test/unit/`
(`cmac_test.cpp`, `authMiddleware_test.cpp`, `clientKeysFileResolver_test.cpp`);
`authMiddleware_test.cpp` exercises `AuthMiddleware` against a scratch
`client.keys` file it writes to `/tmp`, through `ClientKeysFileResolver` --
there is no in-memory stand-in resolver.

**Server shape:** `AuthServer` (`interface/iAuthServer.hpp` + `include/authServer.hpp`
+ `src/authServer.cpp`) carries over the CRTP contract + pimpl split: the CRTP
template lets any concrete transport satisfy `IAuthServer` identically, and the
pimpl'd `Impl` keeps every library-specific type out of the header. Today
`Impl` stores what `configure()`/`setKeyResolver()`/`addRoute()` are given,
builds a real `AuthMiddleware` from that config + resolver on `start()`, and
tracks a plain running flag -- no HTTP library is wired in yet, so
`authServer_test.cpp` only covers that lifecycle shape (no request ever
actually reaches `AuthMiddleware`). RESTinio (the candidate library) is
deliberately left for last: `Impl` gains a real reactor/listener only once
that's picked up, and each connection will dispatch through the middleware
that's already built.

`RemotedModuleFacade::start()`/`stop()` (see `remotedModuleFacade.hpp`) now own an
`AuthServer` and a `ClientKeysFileResolver`, wiring `setKeyResolver()` +
`configure()` + `start()`/`stop()` alongside the heartbeat thread. `configure()`
is called with default `ServerConfig`/`TlsConfig` -- `remoted_module_config_t`
doesn't carry TLS/host/limit knobs yet -- and no routes are registered, since
there is no endpoint logic to hang off it yet. None of this opens a socket
today; it just keeps the wiring current so only `authServer.cpp`'s `Impl`
needs to change once a transport is chosen.

**Agent key resolution:** `ClientKeysFileResolver` reads `etc/client.keys` directly
and parses it the same way the manager's own `OS_ReadKeys()` does (id/name/ip/key
columns, `#`/`!`-marked removed entries skipped), independent of remoted's C
`keystore`. This was a deliberate choice over reaching into remoted's live
`keystore`: remoted loads it in `W_ENCRYPTION_KEY` mode (see `secure.c`), which
never keeps the raw pre-shared key in memory -- only a derived key for the
legacy message cipher -- so the raw key needed for signing has to come from the
file itself. The key column is treated as lowercase hex and hex-decoded as-is
(no further derivation); it must decode to 16, 24 or 32 bytes to work as an
AES-CMAC key. client.keys has no "disabled but present" state -- a removed
entry is simply absent -- so `AuthError` has no separate inactive-agent case;
an unknown and a removed agent are indistinguishable and both resolve to
`AuthError::UnknownAgent`.

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
