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
│   ├── remoted_module.h        # C-ABI: config struct + start/stop (the only C↔C++ contact)
│   └── remotedModule.hpp       # public C++ Singleton facade
├── src/
│   ├── remotedModule.cpp       # extern "C" shims + facade delegation + log sink definition
│   └── remotedModuleFacade.hpp # worker std::thread + cooperative-shutdown lifecycle
└── tests/unit/                 # GoogleTest black-box tests over the C-ABI
```

To grow the module, add sub-libraries under `src/<submodule>/` each with their own
`CMakeLists.txt` (the `vulnerability_scanner` pattern) and link them into `remoted_module`.

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
