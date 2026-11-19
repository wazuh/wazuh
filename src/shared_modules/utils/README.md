# utils — shared header library of the manager and the agent

A header-only grab bag of C++ helpers — logging, threading and dispatch, sockets, RocksDB and SQLite
wrappers, crypto, JSON, string/time/number helpers, the `wazuh-agent+jwt`/`wazuh-enroll+jwt`
implementation — included by the manager's C++ modules, the engine and the agent alike. There is **no
library target**: `CMakeLists.txt` defines nothing to link. Every consumer gets the headers through an
include path (`include_directories(${SRC_FOLDER}/shared_modules/utils)` in `src/CMakeLists.txt` for the
whole tree, `include_directories(${SHARED_MODULES}/utils)` in `src/engine/CMakeLists.txt`) and compiles
what it includes into its own binary.

What `CMakeLists.txt` does register:

- `flatbuffers/` (manager only): the `flatbuffer_tool` executable and the `compile_schemas_input` target
  that runs `flatc` over `flatbuffers/schemas/inventorySync.fbs` into the gitignored
  `flatbuffers/include/` directory, created at build time (`inventorySync_generated.h` + `inventorySync_schema.h`).
  `inventory_sync_server` and `vulnerability_scanner` depend on that target.
- `tests/` and `benchmark/`, only with `UNIT_TEST` and only when the target is not an agent.

Documentation for this library lives in three places, each with its own job:

- **This README** — the developer's map: which headers are load-bearing, what is kept identical
  elsewhere, why, and which lanes test what.
- **Operator/integrator pages** that exist for some parts:
  [FlatBuffers](../../../docs/ref/modules/utils/flatbuffers/README.md) (the schemas and how they are
  generated), the
  [HTTPS agent API](../../../docs/ref/modules/remoted/https-events-api.md) (the JWT bearer profile on
  the wire) and the [keystore](../../../docs/ref/modules/keystore/README.md) page (its use of
  `evpHelper.hpp`). Those pages are the contract; this file does not restate them.
- **Consumer READMEs** for how a header is used in context — remoted's auth middleware and enrollment
  gates in [remoted_module/README.md](../../remoted/remoted_module/README.md), authd's re-enrollment bridge
  in [os_auth/README.md](../../os_auth/README.md).

## Requirements (cross-cutting)

The headers are independent of each other; the requirements every one of them shares are:

| # | Requirement | Where |
|---|---|---|
| RNF-1 | Header-only: no `.cpp`, no archive, nothing to link. A header that needs a dependency (RocksDB, OpenSSL, zlib/minizip, jwt-cpp, rapidjson, sqlite) leaves linking it to the consumer | `CMakeLists.txt`; `target_link_libraries(utils_utest …)` in `tests/CMakeLists.txt` |
| RNF-2 | Every header a C++17 consumer includes must compile as C++17: the engine is C++17, remoted_module is strict C++17, and `utils_utest` pins `CMAKE_CXX_STANDARD 17`. `CMakeLists.txt` sets no standard (it builds nothing; each consumer compiles the headers under its own); `flatbuffers/` pins C++17 for `flatbuffer_tool`, `benchmark/` takes the tree's C++20 | `CMakeLists.txt` (comment), `tests/CMakeLists.txt`, [uds_http_server RNF-1](../uds_http_server/README.md#non-functional) |
| RNF-3 | Shared by manager and agent: the agent's data_provider, syscollector, SCA, agent_info, sync_protocol and https_client include these headers too, so an edit can break an agent build that no manager lane compiles | include sites; `.github/workflows/5_testcomponent_https_client-rtr.yml` `paths:` |
| RNF-4 | Dual-licensed `GPL-2.0-only OR AGPL-3.0-or-later`: every source file needs that SPDX line in its first 30 lines (this README needs none); vendored code is listed in `THIRD_PARTY` instead (`makeUnique.h`) | `.github/scripts/spdx_scope.py`, [COPYING](COPYING) |

## Components

Grouped by purpose. Only the headers with a non-obvious contract get a section below.

| Group | Headers |
|---|---|
| Logging, process, paths | `loggerHelper.h`, `proc.hpp`, `homedirHelper.hpp`, `managerConfDir.hpp`, `cmdHelper.h`, `linuxInfoHelper.h` |
| Threads, queues, dispatch | `threadSafeQueue.h`, `threadSafeMultiQueue.hpp`, `threadDispatcher.h`, `threadEventDispatcher.hpp`, `asyncValueDispatcher.hpp`, `asyncFlushController.hpp`, `msgDispatcher.h`, `filterMsgDispatcher.hpp`, `pipelinePattern.h`, `pipelineNodesImp.h`, `conditionSync.hpp`, `monotonicCondition.hpp`, `abstractWait.h`, `abstractLocking.hpp`, `promiseFactory.h`, `mapWrapperSafe.h` |
| Patterns and RAII | `singleton.hpp`, `builder.hpp`, `chainOfResponsability.hpp`, `observer.hpp`, `defer.hpp`, `customDeleter.hpp`, `cjsonSmartDeleter.hpp`, `uniqueFD.hpp`, `functionTraits.hpp`, `makeUnique.h` (third-party), `cacheLRU.hpp`, `roundRobinSelector.hpp` |
| Strings, numbers, time, JSON, files | `stringHelper.h`, `numericHelper.h`, `timeHelper.h`, `byteArrayHelper.h`, `jsonIO.hpp`, `jsonArrayParser.hpp`, `reflectiveJson.hpp`, `globHelper.h`, `stdFileSystemHelper.hpp`, `zlibHelper.hpp` |
| Crypto and certificates | `hashHelper.h`, `evpHelper.hpp`, `rsaHelper.hpp`, `opensslPrimitives.hpp`, `certHelper.hpp`, `jwt/` |
| Sockets and wazuh-db | `socketWrapper.hpp`, `socketClient.hpp`, `socketServer.hpp`, `epollWrapper.hpp`, `osPrimitives.hpp`, `osPrimitivesImplMac.h`, `osPrimitivesInterfaceMac.h`, `packet.hpp`, `socketDBWrapper.hpp`, `socketDBWrapperException.hpp`, `wazuhDBQueryBuilder.hpp`, `networkHelper.h`, `networkUnixHelper.h` |
| Storage | `rocksDBWrapper.hpp`, `rocksDBQueue.hpp`, `rocksDBQueueCF.hpp`, `rocksDBColumnFamily.hpp`, `rocksDBIterator.hpp`, `rocksDBOptions.hpp`, `rocksDBSharedBuffers.hpp`, `sqlite3Wrapper.hpp`, `sqliteWrapperTemp.h` |
| Windows | `windowsHelper.h`, `registryHelper.h`, `encodingWindowsHelper.h` |
| Test doubles | `mocks/` (`chainOfResponsabilityMock.h`, `sqliteWrapperTempMock.h`) for consumers' tests; `tests/mocks/` for `utils_utest` only |

### `managerConfDir.hpp` — the configuration directory

`Utils::MANAGER_CONF_DIR` is `/etc/wazuh-manager`, fixed and absolute: a custom home moves the home
only. It is one of several copies kept identical **by hand** — `WAZUH_MANAGER_CONF_DIR` in
`src/shared/include/defs.h`, `MANAGER_CONF_DIR` in `src/engine/source/base/include/base/managerConfig.hpp`
and `framework/wazuh/core/common.py`, `CONF_DIR` in `src/init/shared.sh` and in the credential resolver.
Only the resolver's and `common.py`'s are pinned by a test
(`src/init/credentials/tests/test_framework_parity.py`); nothing compares this header to the others.
`Utils::isInManagerConfDir()` is `constexpr` so that a default path spelled as a literal can carry a
`static_assert` next to it (remoted_module does, in `httpServerConfig.cpp`, `installPaths.hpp`,
`keystore.hpp`, `tokenKeySource.hpp` and `passwordKeySource.hpp`). Consumers: manager_config (library
and CLI), manager_certs, remoted_module.

### `loggerHelper.h` — the per-DSO log sink

`Log::GLOBAL_LOG_FUNCTION` is declared `extern` and **defined by each consumer** (one translation unit
per DSO: `vulnerabilityScannerDefs.hpp`, `remotedModule.cpp`, `wdb_http.cpp`, the engine's `logging.cpp`,
`hcInterface.cpp`, the keystore library — which `keystore_server` deliberately reuses instead of defining
its own). Everything in the header is under `#pragma GCC visibility push(hidden)` (D2), so each `.so`
logs through its own sink, set once with `Log::assignLogFunction()` (a second call does not replace the
first). `GLOBAL_LOG_LEVEL` is `inline` for the same reason. The `LOGFN_*` macros skip argument
evaluation below the level; `LOGFN_CRITICAL` is never filtered (D3). This is why
[uds_http_server](../uds_http_server/README.md) must be static (its RNF-2).

### `jwt/` — the agent authentication profiles

The header-only implementation of the closed `wazuh-agent+jwt` profile (`jwtProfileV1.hpp`: an agent
self-signs an HS256 bearer with its `client.keys` secret) and the `wazuh-enroll+jwt` profile
(`jwtEnrollProfileV1.hpp`: `POST /enroll`, with or without a `kid`). Signers and verifiers for both,
the shared compact grammar and time rules (`jwtCompactGrammar.hpp`), HKDF-SHA256 key derivation with
three domain-separating `info` labels (`enrollKeyDerivation.hpp`), the strict ASCII-only JSON object
parser (`strictJsonObject.hpp`), the canonical agent id (`canonicalAgentId.hpp`), key decoding
(`jwtKeyDecoder.hpp`: exactly 64 lowercase hex chars → 32 bytes, never the ASCII text), the
low-cardinality failure classes (`jwtVerifyError.hpp`) and a move-only, `OPENSSL_cleanse`d key buffer
(`secureBytes.hpp`). Verifiers are fail-closed and stateless, and no exception leaves a public function.
Built on jwt-cpp's base64url (`ext_jwt_cpp`, linked by the consumer), rapidjson's SAX reader and
OpenSSL 3. One implementation serves both sides: remoted_module and authd (`os_auth/src/reenroll_verify.cpp`)
verify, the agent's https_client signs. The wire rules are on the
[HTTPS agent API](../../../docs/ref/modules/remoted/https-events-api.md) page.

**`jwt/testVectors.hpp` is mirrored**: frozen vectors, test-only (nothing in production includes it),
copied into `tools/manager_benchmark/tool_simulator/internal/wire/testdata/jwt_vectors.json` for the Go
simulator. `tools/manager_benchmark/tests/test_jwt_vectors_mirror.py` compares the two (and fails on a
header constant the JSON does not carry); a third copy as `#define`s in cmocka tests under
`src/unit_tests/` (for example `shared/test_b64url_op.c`, `shared/test_enrollment_token.c`) is compared
by nothing. authd re-implements the enrollment-token derivation in C (`src/shared/src/enrollment_token.c`);
the vectors are what keep the two byte-identical.

### `socketDBWrapper.hpp` — the C++ wazuh-db client

A `Singleton` over `SocketClient<Socket<OSPrimitives, SizeHeaderProtocol>, EpollWrapper>` that sends one
query at a time and blocks for its answer, decoding the wazuh-db reply prefixes (`ok`, `err`, `ign`, `unk`,
`due` — `due` chunks accumulate until the closing `ok`). A `{"status":"NOT_SYNCED"}` answer throws
`SocketDbWrapperException`; every other failure throws `std::runtime_error`. Its default path is its own
literal, `WDB_SOCKET` = `queue/sockets/wdb.sock`, a spelling of the socket separate from `WDB_LOCAL_SOCK`
in `src/shared/include/defs.h` and `WDB_SOCKET` in `framework/wazuh/core/common.py` — a socket rename must
change it too. Consumer today: vulnerability_scanner (`init()` in `vulnerabilityScannerFacade.cpp`).
`wazuhDBQueryBuilder.hpp` builds the query strings.

### Other headers with a contract

| Header | Contract | Consumers |
|---|---|---|
| `monotonicCondition.hpp` | A condition variable pinned to `CLOCK_MONOTONIC` through `pthread_condattr_setclock`, used with `std::mutex`/`std::unique_lock` (D7). Non-Linux keeps the standard implementation | https_client, sync_protocol |
| `proc.hpp` | Processor count for thread pools: on Linux the minimum of the affinity mask and the cgroup CPU quota (v2 `cpu.max` first, then v1 `cpu.cfs_quota_us`/`cpu.cfs_period_us`), a fractional quota rounded up, never 0 (D8) | dbsync, inventory_sync_server, remoted_module, uds_http_server, vulnerability_scanner; `threadDispatcher.h`, `asyncValueDispatcher.hpp` |
| `sqlite3Wrapper.hpp` | Every connection sets `sqlite3_busy_timeout` to `DB_BUSY_TIMEOUT_MS` (5000) (D9) | wazuh-db's HTTP handlers (`src/wazuh_db/src/http/`), sync_protocol |
| `homedirHelper.hpp` | `Utils::findHomeDirectory()`: `WAZUH_MANAGER_HOME` (`WAZUH_AGENT_HOME` when `CLIENT` is defined) when set and non-empty, else the parent of `/proc/self/exe`'s directory when that is `bin` (D12) | keystore |
| `certHelper.hpp` | `Utils::CertHelper::mergeCaRootCertificates()` writes the merged CA bundle owned by the account running the process, not a fixed user name (D10) | indexer_connector |
| `asyncFlushController.hpp` | Runs a caller-supplied blocking flush in one worker thread and keeps the last result | SCA, syscollector |
| `rocksDBWrapper.hpp` and the `rocksDB*` family | RocksDB database, column families, transactions, queues | content_manager, keystore, vulnerability_scanner |
| `socketServer.hpp` | epoll-based socket server template; the socket type and its framing protocol come from `socketWrapper.hpp` | keystore_server |
| `reflectiveJson.hpp` | Compile-time JSON serialisation of any type exposing a static `fields()` (plus strings, numbers, maps, vectors, lists) | indexer_connector, wazuh-db's HTTP handlers |
| `evpHelper.hpp` | AES-256-CBC with a per-value random key and IV ([keystore](../../../docs/ref/modules/keystore/README.md)) | keystore |

## Design decisions

Only decisions whose reason is written down in the code or its history are listed.

| # | Decision | Why |
|---|---|---|
| D1 | One `MANAGER_CONF_DIR` per language, and a `constexpr` `isInManagerConfDir()` for `static_assert`s | A `const char*` default cannot be concatenated at compile time, so defaults stay literals and the assertion keeps each literal from drifting from the directory (comment in `managerConfDir.hpp`) |
| D2 | `loggerHelper.h` is wrapped in `#pragma GCC visibility push(hidden)` | `GLOBAL_LOG_FUNCTION`/`GLOBAL_LOG_LEVEL` must stay private to each DSO; otherwise the dynamic linker interposes same-named inline symbols across shared objects and one `.so` runs another's copy, reading its unset globals (comment in the header) |
| D3 | `LOGFN_CRITICAL` has no level gate | The C/C++ logging bridge every module uses (`mtLoggingFunctionsWrapper`, `src/shared/src/debug_op.c`) logs and `exit(1)`s on that level, the same sequence as `_merror_exit()`, for a configuration that can never work; it must never be dropped (comment in the header) |
| D4 | HMAC-SHA256 through OpenSSL's one-shot `EVP_Q_mac`, not jwt-cpp's `hs256` | jwt-cpp copies the key into a `std::string` it never wipes; here the key bytes never leave `SecureBytes` (comment in `jwt/hmacSha256.hpp`) |
| D5 | A purpose-built strict JSON parser (`StrictJsonObject`) instead of a generic JWT library's | Exact member allowlist, fixed types, no duplicates or nesting, ASCII only, never reading past the given length — strictness a generic JWT library cannot offer, pinned by `src/remoted/remoted_module/test/unit/jwtCppSpike_test.cpp` (comment in `jwt/strictJsonObject.hpp`) |
| D6 | The JWT test vectors were generated with Python's standard library | An oracle independent of this library (comment in `jwt/testVectors.hpp`) |
| D7 | `MonotonicCondition` instead of `std::condition_variable::wait_for` | libstdc++ keeps `wait_for` monotonic only when built with `_GLIBCXX_USE_PTHREAD_COND_CLOCKWAIT` (glibc ≥ 2.30); the agent's toolchain predates that, so a backward clock jump extended every wait by the jump (commit that added the header) |
| D8 | `proc.hpp` honours the cgroup CPU quota | So the count reflects container/pod CPU limits instead of the full node capacity (comment in the header) |
| D9 | A 5 s SQLite busy timeout on every connection | Without it a transient lock — e.g. a previous instance whose WAL handle is not yet released across a fast restart — surfaces at once as `SQLITE_BUSY` instead of resolving (comment in `sqlite3Wrapper.hpp`) |
| D10 | `certHelper.hpp` chowns to the running account | The manager package creates `wazuh-manager` and removes `wazuh`, which the agent package creates; either literal is wrong on the other side (comment in the header) |
| D11 | Dual licence `GPL-2.0-only OR AGPL-3.0-or-later` | The library is linked both by the AGPLv3 engine and by GPLv2-only code (the C daemons, remoted_module, the agent); each consumer takes the licence that matches it (commit that introduced [COPYING](COPYING)) |
| D12 | `findHomeDirectory()` reads a per-target environment variable first | Manager/agent separation for co-hosted installs (comment in `homedirHelper.hpp`) |

## Layout

| Path | Content |
|---|---|
| `*.h`, `*.hpp` | The headers (see [Components](#components)) |
| `jwt/` | The JWT profiles and their frozen vectors |
| `flatbuffers/` | `schemas/inventorySync.fbs`, `flatbuffer_tool` (`flatbuffers/src/main.cpp`, `flatbuffers/src/argsParser.hpp`) and the generation rules; output in the gitignored `include/` |
| `mocks/` | GMock doubles for consumers |
| `tests/` | `utils_utest` sources, `tests/mocks/`, `input_files/` (copied into the build tree) |
| `benchmark/` | `utils_benchmark_test` (Google Benchmark; the RocksDB queue on Linux), a manual tool |
| `COPYING` | The dual-licence notice |

## Tests

`tests/` builds `utils_utest` (GTest, C++17, label `utils_utest`) on the manager only. On Linux it links
`FileIO` from [file_helper](../file_helper/README.md) (for `linuxInfoHelper.h`), RocksDB, OpenSSL, zlib and
minizip. The sources are listed explicitly in `tests/CMakeLists.txt` — a new `*_test.cpp` is not built until
it is added there. The Windows-only sources
(`windowsHelper_test.cpp`, `registryHelper_test.cpp`, `encodingWindows_test.cpp`) are built only for a
Windows target, which no manager lane is.

`benchmark/` builds `utils_benchmark_test`, a **manual** tool that no CI lane builds or runs. Its ctest
entry (label `utils_benchmark`, outside the `-L utils_utest` selection) passes
`--benchmark_min_time=0.01`, so a plain `ctest` only smoke-runs it; for real numbers run the binary
itself, from a scratch directory (it creates a RocksDB `test.db` in the working directory):

```bash
cmake --build build -j --target utils_benchmark_test
(cd "$(mktemp -d)" && "$OLDPWD/build/bin/utils_benchmark_test")
```

From `src/`, in a tree configured with `UNIT_TEST=ON` (see the `wazuh-build` and `wazuh-testing` skills):

```bash
cmake --build build -j --target utils_utest
ctest --test-dir build -L utils_utest --output-on-failure
```

Several headers are tested only by their consumers, so their lanes are the gate:

| Header(s) | Covered by | Lane |
|---|---|---|
| everything compiled into `utils_utest` | `utils_utest` (coverage job, functions floor off; ASAN job) | `.github/workflows/5_testunit_shared_modules_utils.yml` (excludes `jwt/**` and `mocks/**`: no `utils_utest` source includes them) |
| `jwt/**` | remoted_module's unit tests (`jwtVerify_test.cpp`, `jwtEnrollSignVerify_test.cpp`, `strictJsonObject_test.cpp`, `enrollKeyDerivation_test.cpp`, …); https_client's (`jwtSigner_test.cpp`, `enrollSigner_test.cpp`) | `.github/workflows/5_testcomponent_remoted_module.yml`, `.github/workflows/5_testcomponent_https_client-rtr.yml` |
| `jwt/testVectors.hpp` ↔ `jwt_vectors.json` | `test_jwt_vectors_mirror.py` | `.github/workflows/5_testunit_dev-tools.yml` |
| `managerConfDir.hpp` | manager_config and manager_certs suites | `.github/workflows/5_testunit_managerconfig.yml`, `.github/workflows/5_testunit_managercerts.yml` |
| `loggerHelper.h`, `proc.hpp` | uds_http_server suite | `.github/workflows/5_testunit_uds_http_server.yml` |
| `*.cpp`/`*.hpp` formatting (not `*.h`) | clang-format | `.github/workflows/5_codelinter_clangformat.yml` |

## License

Dual-licensed under `GPL-2.0-only OR AGPL-3.0-or-later`; see [COPYING](COPYING). `makeUnique.h` is
third-party (from the N3656 paper) and listed in `THIRD_PARTY` of `.github/scripts/spdx_scope.py`.
