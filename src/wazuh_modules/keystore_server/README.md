# keystore_server — the keystore over `queue/sockets/keystore.sock`

The `wazuh-manager-modulesd` module that exposes the [keystore library](../../shared_modules/keystore/README.md)
to callers that cannot link it. It binds `queue/sockets/keystore.sock`, reads length-prefixed text
queries (`GET|<family>|<key>`, `PUT|<family>|<key>|<value>`, `DELETE|<family>|<key>`) and answers each
with one JSON object. It holds no storage or crypto logic of its own: every request becomes one
`Keystore::get()` or `Keystore::put()`.

Its one production consumer is the Python framework: `KeystoreClient`
(`framework/wazuh/core/indexer/credential_manager.py`) fetches the `indexer` username and password
every time `framework/wazuh/core/indexer/indexer.py` builds an Indexer client. The C++ components do not
go through this module — the Indexer Connector links the library directly.

Two documentation layers cover it, each with its own job:

- **This README** — the developer's map: the [requirements](#requirements), the
  [design decisions](#design-decisions-d1d8), the [C ABI and modulesd wiring](#c-abi-and-modulesd-wiring),
  the [wire contract](#wire-contract) and the [tests](#tests).
- **[`docs/ref/modules/keystore/`](../../../docs/ref/modules/keystore/README.md)** — the operator
  reference; its [`keystore_server`](../../../docs/ref/modules/keystore/README.md#keystore_server)
  section states the loading, transport and protocol as operators see them, and
  [concurrent access](../../../docs/ref/modules/keystore/README.md#concurrent-access) what a busy
  database means for a request.

The storage, the column families, the lock waits and the format version belong to the
[library's README](../../shared_modules/keystore/README.md); they are not repeated here.

## Requirements

### Functional (RF)

| # | Requirement | Where |
|---|---|---|
| RF-1 | Bind `queue/sockets/keystore.sock` (relative to modulesd's working directory, the manager home) as a `SocketServer<Socket<OSPrimitives, SizeHeaderProtocol>, EpollWrapper>`; the socket is made 0660 by `bindUnix()` in `src/shared_modules/utils/socketWrapper.hpp` | `keystore_server_start()` in `src/keystoreServer.cpp` |
| RF-2 | `PUT` stores the value and answers `{"status":"ok","operation":"put","columnFamily":…,"key":…}`; `GET` answers the same shape with `"operation":"get"` and `"value"` | `PutThenGetRoundTrips` |
| RF-3 | A `GET` of a key that was never set answers `"status":"ok"` with an **empty** `value` | `AMissingKeyAnswersAnEmptyValue` (D5) |
| RF-4 | `DELETE` is a `put()` of an empty value, answered with `"operation":"delete"`, and reads back empty | `DeleteIsAPutOfEmptyAndReadsBackEmpty` |
| RF-5 | An operation other than `GET`/`PUT`/`DELETE` answers `{"status":"error","message":"Unknown operation"}` | `AnUnknownOperationIsAnError` |
| RF-6 | A query with fewer than two `\|` separators, including an empty frame, answers `{"status":"error","message":"Invalid query format"}`, and the server keeps serving | `AMalformedQueryIsAnErrorNotACrash`, `AnEmptyFrameIsAnsweredWithAnError` |
| RF-7 | Any exception from the library (a `KeystoreLockTimeout` after `Keystore::DEFAULT_LOCK_WAIT`, an open or crypto failure) is answered as `{"status":"error","message":<what()>}` | the `catch` in `handleRequest()`; not covered by a test |
| RF-8 | `keystore_server_stop()` is idempotent and the module can be started again; a second `keystore_server_start()` while running logs a warning, returns 0 and keeps the first server | `StopIsIdempotentAndTheModuleRestarts`, `ADoubleStartIsToleratedAndKeepsServing` |
| RF-9 | A socket that cannot be bound makes `keystore_server_start()` return -1, and the shim then stops modulesd (`mterror_exit`) | `src/keystoreServer.cpp`, `src/wazuh_modules/src/wm_keystore_server.c` (D2); not covered by a test |
| RF-10 | The module is loaded on every manager, with no configuration section and no tunable | `wm_config()` in `src/wazuh_modules/src/wmodules.c` (D3) |

### Non-functional (RNF)

| # | Requirement | Where |
|---|---|---|
| RNF-1 | `libkeystore_server.so` (C++, SHARED) next to the other manager libraries, RUNPATH `$ORIGIN/../lib`; links the keystore library statically | `CMakeLists.txt` |
| RNF-2 | Requests are served one at a time on the socket server's single listen thread (`m_listenThread` in `src/shared_modules/utils/socketServer.hpp`), and each opens the database synchronously — a lock held elsewhere delays every client of the socket by up to `DEFAULT_LOCK_WAIT` (5 s) per request | `handleRequest()` runs inside the `listen()` callback |
| RNF-3 | No access control besides the socket's mode: anything that can connect can read and overwrite any family (a `PUT` to an unknown family creates it) | `src/keystoreServer.cpp`; the [library's RF-1](../../shared_modules/keystore/README.md#requirements) |
| RNF-4 | The configuration dump lists the module and nothing else: no secret and no setting ever leave through `getconfig` | `wm_keystore_server_dump()` (D7) |
| RNF-5 | Log tag `wazuh-manager-modulesd:keystore-server`, on both sides of the ABI | `KEYSTORE_SERVER_LOGTAG` in `src/keystoreServer.cpp`; `WM_KEYSTORE_SERVER_LOGTAG` (`ARGV0 ":keystore-server"`) in `src/wazuh_modules/src/wm_keystore_server.h` |

<a id="design-decisions-d1d8"></a>

## Design decisions (D1–D8)

| # | Decision | Rationale (and where it is recorded) |
|---|---|---|
| D1 | **The socket has its own minimal module** | It used to be hosted by the legacy inventory_sync module, "an accident of history": the keystore has nothing to do with inventory synchronization. A module of its own is what let that module retire without taking the API's indexer access down with it (header comment of `include/keystore_server.h`) |
| D2 | **An unbindable socket, a missing `.so` or a missing symbol stops modulesd** | An unbindable keystore socket means the manager API silently loses its indexer credentials, and "a manager that looks healthy while its API cannot reach the indexer is worse than one that refuses to run" (comments in `wm_keystore_server_main()` and on `keystore_server_start()`) |
| D3 | **No configuration: a fixed socket path, a `wm_keystore_server_read()` called unconditionally** | The framework's `KeystoreClient` hardcodes the path, so there is nothing to configure (comments in `wm_keystore_server.c` and `wm_keystore_server.h`). The `socketPath` argument exists for the tests only; the shim always passes `NULL` |
| D4 | **The pipe protocol was moved verbatim and is frozen** | It is a live contract with `KeystoreClient`, "so nothing about it may change here" (comment on `handleRequest()`); the unit suite pins it byte for byte for that reason (its file comment). The one deliberate change is D5 |
| D5 | **A `GET` of an absent or empty value answers an empty value, never a default** | The handler used to answer the literal `wazuh-manager`: a known credential for a key nobody set, and no way to tell "not set" from "set to `wazuh-manager`" — the question the credential resolver has to answer (comment in the `GET` branch; the test `AMissingKeyAnswersAnEmptyValue` adds that the framework turns the empty answer into error 2201 instead of authenticating with a guessable password) |
| D6 | **`keystore_server_start()` returns at once; teardown is the `.stop` callback** | The socket server owns its epoll thread, so modulesd's thread for this module exits as soon as the start returns (comment at the end of `wm_keystore_server_main()`; comment in `keystore_server_stop()`: the server's destructor stops the loop and closes the socket) |
| D7 | **`dump` returns an empty `keystore_server` object** | No tunables, a fixed path, and the contents are secrets by definition; the object exists so `getconfig wmodules` lists the module as present (comment in `wm_keystore_server_dump()`) |
| D8 | **This module does not define `Log::GLOBAL_LOG_FUNCTION`** | The statically linked keystore library already defines it, and the module routes its own logging through that symbol (comment at the top of `src/keystoreServer.cpp`) |

## C ABI and modulesd wiring

The module is the three pieces every modulesd module is:

| Piece | Path | Notes |
|---|---|---|
| Implementation | `src/keystoreServer.cpp` → `libkeystore_server.so` | the request handler and the two exported functions |
| ABI header | `include/keystore_server.h` | `keystore_server_start(full_log_fnc_t callbackLog, const char* socketPath)` → 0 or -1; `keystore_server_stop(void)`; the typedefs `keystore_server_start_func`/`keystore_server_stop_func`, which the shim's `dlsym` results are stored in — load-bearing, says the header |
| Shim | `src/wazuh_modules/src/wm_keystore_server.c`, `wm_keystore_server.h` | `so_get_module_handle("keystore_server")` + `so_get_function_sym()`; passes `mtLoggingFunctionsWrapper` and `NULL`; `WM_KEYSTORE_SERVER_CONTEXT` with `start`, `stop`, `destroy`, `dump` (no `sync`, no `query`) |

Wiring, all in the server branches:

- `src/wazuh_modules/CMakeLists.txt` adds the subdirectory and links `keystore_server` **PUBLIC** into
  `wazuh_modulesd_lib`, so modulesd also links the `.so` at build time; the shim still resolves both
  entry points with `dlsym` at start.
- `wm_config()` in `src/wazuh_modules/src/wmodules.c` calls `wm_keystore_server_read()` outside any
  section loop, between `content_manager` and `inventory_sync_server`. Removing it from there is the only
  way to stop loading the module — see the `wazuh-modulesd-module` skill for the general rule.
- `InstallServer` in `src/init/inst-functions.sh` installs `build/lib/libkeystore_server.so`
  (`root:wazuh-manager` 0750) **only if the file exists**: a build that did not produce it installs
  without it, and modulesd then exits at start with `Unable to load libkeystore_server.so`. The installed
  row is pinned by `.github/actions/check_files/manager_base.csv`.
- **The agent build compiles the shim too.** Its branch of `src/wazuh_modules/CMakeLists.txt` globs every
  `src/wazuh_modules/src/*.c` and keeps `keystore_server/include` on the include path; only the call in
  `wmodules.c` sits in its non-`CLIENT` branch. An edit to `wm_keystore_server.c` or `include/keystore_server.h`
  that does not compile reds the agent lanes as well.

## Wire contract

The transport is `SizeHeaderProtocol` (`src/shared_modules/utils/socketWrapper.hpp`): each frame is a
4-byte `uint32_t` length in host byte order followed by the body, and the answer comes back framed the
same way. The framework packs the header `<I` (`framework/wazuh/core/wazuh_socket.py`).

Parsing (`handleRequest()`): the operation is the text before the first `|`, the family the text before
the second, the key the text before a third `|` (or the rest), and the value everything after the third
`|` — so a `PUT` value may itself contain `|`, while a key or family cannot. Extra fields after a `GET` or
`DELETE` key are ignored.

The other end of the contract, and what each side must keep in step:

- `KeystoreClient.get/put/delete()` build the three queries, and `send_query()` parses the answer as
  JSON. A change to an operation name, a separator or a response field moves both files.
- The socket path is spelled in `KEYSTORE_SOCKET_PATH` here and in `KEY_STORE_SOCKET`
  (`framework/wazuh/core/common.py`); `src/shared/include/defs.h` has no constant for it. A rename means
  editing both literals.
- `indexer.py` reads `value` only, and treats an empty or missing value as error 2201.

## Layout

```
keystore_server/
├── CMakeLists.txt                       # SHARED lib into ${CMAKE_BINARY_DIR}/lib; tests under UNIT_TEST
├── include/keystore_server.h            # the C ABI modulesd dlsym()s
├── src/keystoreServer.cpp               # socket server, request handler, start/stop
└── test/unit/keystoreServerProtocol_test.cpp   # keystore_server_utest
```

## Tests

| Suite | Covers | CI lane |
|---|---|---|
| `test/unit/keystoreServerProtocol_test.cpp` (`keystore_server_utest`, ctest label `keystore_server_utest`) | RF-2 – RF-6 and RF-8 through a real socket in `/tmp` and a real RocksDB in `queue/keystore` under the test's working directory; a minimal `SizeHeaderProtocol` client, one request per connection, with a 5 s receive timeout | [`5_testunit_keystoreserver.yml`](../../../.github/workflows/5_testunit_keystoreserver.yml): a job with the suite and a coverage report (threshold `0`: the suite had no lane before, so there was no number to pin), and an ASAN job; both `allowed_skips: 0`, valgrind off |
| `framework/wazuh/core/indexer/tests/test_credential_manager.py` | `KeystoreClient` against a mocked `WazuhSocket` — the client's half of the wire contract, never this server | `5_testunit_framework.yml` |
| `test_manager_control/` (whole-manager integration) | the installed `.deb` started, restarted and reloaded with every daemon, modulesd included, asserted running — which this module's fatal paths (D2) would break | selected by `src/**` in `.github/test_modules_manager.json`, from `5_builderpackage_manager-multiples.yml` |

Also: [`5_codelinter_clangformat.yml`](../../../.github/workflows/5_codelinter_clangformat.yml) checks the
`.cpp`/`.hpp` files here. RF-7 (an error from the library), RF-9 (a failed bind) and more than one query
on one connection — which `indexer.py` does, two `GET`s inside one `with KeystoreClient()` — have no
test. There is no `qa/` harness and no test tool for this socket.

To reproduce the unit suite locally:

```bash
cmake -S src -B src/build -DUNIT_TEST=ON
cmake --build src/build -j --target keystore_server_utest
ctest --test-dir src/build -L keystore_server_utest --output-on-failure
```

## License

GPL-2.0 (the file headers of `include/` and `src/`). The keystore library it links is dual-licensed —
see [its README](../../shared_modules/keystore/README.md#license).
