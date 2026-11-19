# keystore — the manager's secret store (`queue/keystore`)

Manager-only C++20 static library over a RocksDB database at `queue/keystore` (relative to the
manager home), plus the `bin/wazuh-manager-keystore` command-line tool built from the same directory.
Values are kept per **column family** (a namespace); the one family the manager uses is `indexer`
(`username`, `password`: the account the manager presents to the Wazuh Indexer). Every value is
encrypted with AES-256-CBC by `Utils::EVPHelper` before it is written.

Who uses it:

- the **Indexer Connector** (`src/shared_modules/indexer_connector/`), which reads the `indexer` family
  once per process — so inside `wazuh-manager-modulesd` (vulnerability scanner, inventory sync server)
  and `wazuh-manager-analysisd` (the engine's `wiconnector`);
- **[`keystore_server`](../../wazuh_modules/keystore_server/README.md)**, the modulesd module that
  serves the library to the Python framework over `queue/sockets/keystore.sock`;
- **`wazuh-manager-keystore`**, run by operators and by the
  [credential resolver](../../init/credentials/README.md), which writes the `indexer` entries at
  installation and before every start;
- the test tools of `indexer_connector`, `inventory_sync_server` and `vulnerability_scanner`, which seed
  credentials with `Keystore::put()`.

Two documentation layers cover the keystore, each with its own job:

- **This README** — the developer's map: the [requirements](#requirements), the
  [design decisions](#design-decisions-d1d9), the [consumer contract](#consumer-contract), the
  [layout](#layout) and the [tests](#tests).
- **[`docs/ref/modules/keystore/`](../../../docs/ref/modules/keystore/README.md)** — the operator
  reference: [storage and column families](../../../docs/ref/modules/keystore/README.md#storage),
  [CLI usage](../../../docs/ref/modules/keystore/README.md#cli-usage) (every flag and exit status),
  [concurrent access](../../../docs/ref/modules/keystore/README.md#concurrent-access) (the lock waits
  and when a repair runs), and the
  [format version](../../../docs/ref/modules/keystore/README.md#format-version). Those facts live
  there; this file links them.

How the resolver drives the CLI, and when it may, is the resolver's contract — see its
[README](../../init/credentials/README.md) (RF-4, D-23, D-25).

## Requirements

### Functional (RF)

| # | Requirement | Where |
|---|---|---|
| RF-1 | `Keystore::put(family, key, value)` encrypts the value, creates the family when it does not exist, stamps the format version in that family, and writes the ciphertext | `src/keyStore.cpp`; `TestPutGet` |
| RF-2 | `Keystore::get(family, key, value)` decrypts and returns the stored value; an absent key leaves `value` empty; the two-argument overload `get(family, key)` returns it | `src/keyStore.cpp`; `TestPutGet` |
| RF-3 | A `get()` from a family that does not exist returns an empty value **without creating the family** | `src/keyStore.cpp`; `TestGetDoesNotCreateColumnFamily` (D4) |
| RF-4 | Every operation opens the database for itself and closes it before returning | `openKeystore()` in `src/keyStore.cpp` (D1) |
| RF-5 | An operation that finds the database lock held waits for it, up to a caller-supplied bound (`DEFAULT_LOCK_WAIT` 5 s, `CLI_LOCK_WAIT` 30 s); past the bound it throws `KeystoreLockTimeout` and has read or written nothing | `include/keyStore.hpp`; `TestGetWaitsForAnotherHandleInsteadOfRepairing`, `TestALockHeldPastTheWaitIsReportedAsBusyAndChangesNothing`, `TestTheCallersWaitIsHonoured`, `TestTheCliWaitsLongerThanTheDaemons` (D2) |
| RF-6 | Concurrent readers and writers in one process all succeed, and none triggers a repair | `TestConcurrentAccessSucceeds` (asserts no `lost/` directory, which `RepairDB` leaves) (D3) |
| RF-7 | The CLI writes a value given inline (`-v`), from the first line of a file (`-vp`) or from the first line of standard input, into `-f <family>` / `-k <key>` | `src/main.cpp`; `qa/test_keystore.py::test_keystore_parameters` (five insertion methods × four passwords, read back through the testtool) |
| RF-8 | The CLI's `-g` prints the stored value and exits 0; an unset or empty key exits 1 and prints nothing; `-g` with a value is a usage error | `src/main.cpp`; `test_keystore_get_returns_the_stored_value`, `test_keystore_get_of_an_unset_key_exits_non_zero`, `test_keystore_get_rejects_a_value_argument` (D6) |
| RF-9 | The CLI names an unknown option (`Unknown option: <arg>`) and exits 1 before the keystore is opened; the argument after `-f`, `-k`, `-v` or `-vp` is that option's value and is never taken for an option, so a value may start with `-` (`-v -g` writes `-g`) | `rejectUnknownSwitches()`, `hasSwitch()` and `takesValue()` in `src/argsParser.hpp`; `test_keystore_unknown_option_is_named` (D7). No test passes a value that starts with `-` |
| RF-10 | Run as root, the CLI moves to the manager home (`Utils::findHomeDirectory()`: `WAZUH_MANAGER_HOME`, else the parent of `bin/`) and switches to `wazuh-manager:wazuh-manager` (umask `0007`) before it opens the database; a `-vp` file is opened before the switch. Without those accounts (a build-tree run) it keeps its identity | `dropPrivilegesIfAvailable()` in `src/main.cpp`; not covered by a test |
| RF-11 | A lock timeout in the CLI is reported as `The keystore is busy: … Run the command again.` with exit 1 | the `KeystoreLockTimeout` handler in `src/main.cpp`; not covered by a test |

### Non-functional (RNF)

| # | Requirement | Where |
|---|---|---|
| RNF-1 | STATIC library, `-fPIC`, C++20; built only for the manager (`add_subdirectory(shared_modules/keystore)` in the `if(NOT IS_AGENT)` branch of `src/CMakeLists.txt`) | `CMakeLists.txt` |
| RNF-2 | The CLI keeps the hardening flags passed by `src/Makefile` and links with `-pie` on Linux | `CMakeLists.txt` (D9) |
| RNF-3 | The database is opened without the write-ahead log, with repair-on-corruption on and a private 16 MiB read cache | `openKeystore()` (`RocksDBWrapper(DATABASE_PATH, false, true, false, …)`) |
| RNF-4 | Dual-licensed `GPL-2.0-only OR AGPL-3.0-or-later`: every source file carries the SPDX line, enforced by the SPDX lane through `.github/scripts/spdx_scope.py` (`DUAL_DIRS`; this README is out of its scope) | `COPYING` (D8) |

<a id="design-decisions-d1d9"></a>

## Design decisions (D1–D9)

| # | Decision | Rationale (and where it is recorded) |
|---|---|---|
| D1 | **One RocksDB handle per operation, never a long-lived one** | A handle holds RocksDB's `LOCK` file for as long as it lives, and the database is shared by separate processes (modulesd, the engine, the CLI the resolver runs before every start): a long-lived handle in one would lock the others out. The cost is one open per request, cheap next to the permanent refusal a long-lived handle would cause. At idle the requests come from the master's framework, two (`username`, `password`) each time it builds an Indexer client (`get_indexer_client()` in `framework/wazuh/core/indexer/indexer.py`): the active-response poll every 30 s (`active_response_polling`), which builds two clients per cycle even when it finds nothing, and the indexer-check, disconnected-agent and metrics tasks every few minutes. Each open of the read-write database writes a new `MANIFEST`, write-ahead log and `OPTIONS` file, so the file numbers in `queue/keystore/` climb faster than the opens; they are not an open counter. Comment above `openKeystore()` |
| D2 | **Contention is waited out with a jittered backoff; the CLI waits longer (30 s) than a daemon (5 s)** | Callers that lost the same race retried on the same schedule and collided again; the jitter spreads them (`jitteredLockRetryDelay()` in `utils/rocksDBWrapper.hpp`). Daemons serve callers that retry, so they keep a short wait; the CLI runs once, and a burst of daemon reads should delay it, not fail it (comments on `DEFAULT_LOCK_WAIT`/`CLI_LOCK_WAIT` in `include/keyStore.hpp`). `KeystoreLockTimeout` is a distinct type so a caller can tell "busy, nothing changed, retry" from a real failure |
| D3 | **A held lock is never treated as corruption; only `Status::Corruption` is repaired** | Repairing a live database is unsafe and `RepairDB` would need the same lock anyway (`repairDB()` and `isLockContention()` in `utils/rocksDBWrapper.hpp`). The keystore opens with `repairIfCorrupt` on, so the guarantee comes from the wrapper |
| D4 | **A read never creates a column family** | It let any reader add families that nothing reads and nothing removes, each with a version row (comment in `Keystore::get()`; the commit that introduced it says the same) |
| D5 | **The format version (`version` = `2`) is stamped on every `put()`, and nothing is migrated** | No pre-5.0 keystore reaches this code, since the manager is not upgraded in place across the 4.x → 5.x boundary; the field is kept so a future format change can key off it (comment on `upgrade()` in `src/keyStore.cpp`) |
| D6 | **The CLI can read back (`-g`); "absent" and "empty" are one answer, exit 1, printed silently** | The resolver must know whether a credential is already in the store, and inferring that from a config file or a shipped default "makes every restart a guess"; exiting non-zero lets a shell test it directly, and "not set" is an answer, not an error (comments in `src/main.cpp`) |
| D7 | **Unknown options are rejected before any other argument is parsed** | So a mistyped flag is named instead of being reported as a missing `-f` or `-k`, or silently ignored next to them (comment on the `CmdLineArgs` constructor in `src/argsParser.hpp`) |
| D8 | **Dual licence `GPL-2.0-only OR AGPL-3.0-or-later`** | The library is linked both by the AGPLv3 engine (through the Indexer Connector) and by GPLv2-only code; all of it is authored by Wazuh, so each consumer takes the licence that matches it (the commit that dual-licensed `utils`, `manager_config`, `keystore` and `indexer_connector`) |
| D9 | **`CMakeLists.txt` appends to the inherited `CMAKE_CXX_FLAGS` and adds `-pie`** | It used to overwrite them, dropping the stack protector and `FORTIFY_SOURCE` flags `src/Makefile` passes; the fix follows `syscheckd` (the commit that hardened the CLI) |

## Consumer contract

- **API**: two static functions in `include/keyStore.hpp` — `put()` and `get()` (plus the convenience
  `get(family, key)` that returns the value). There is no delete: `keystore_server` implements its
  `DELETE` as a `put()` of an empty value, and the resolver's `--clear` empties the whole directory.
- **Working directory**: the path `queue/keystore` is relative. modulesd (`src/wazuh_modules/src/main.c`),
  the engine (`src/engine/source/main.cpp`) and the CLI move to the manager home first; a test must
  create `queue/` in its working directory before its first `put()` — the comment in
  `indexer_connector/tests/component/indexerConnector_test.cpp` and the testtool both rely on this.
- **Exceptions**: `put()`/`get()` throw `KeystoreLockTimeout` (lock still held after `lockWait`) or
  another `std::exception` (open, repair or crypto failure). Pass `Keystore::CLI_LOCK_WAIT` only from a
  run-once tool; daemons keep the default.
- **Read once, restart to rotate**: the Indexer Connector keeps the credentials in function-local
  statics (`buildSecureCommunication()` in
  [`indexerTransport.cpp`](../indexer_connector/src/indexerTransport.cpp)), so a new value reaches
  modulesd and the engine only after a restart. The framework, through `keystore_server`, reads them
  again for every Indexer client it builds.
- **Who may open it, and when**: the resolver's writing modes open the database read-write, so
  `wazuh-manager-control` runs `--prestart` only while modulesd is down (`resolvecredentials()` in
  `src/init/wazuh-server.sh`, after the stop on `restart`). The lock waits above make a concurrent CLI
  run safe; the ordering is what the control script still enforces.
- **Logging**: `src/keyStore.cpp` **defines** `Log::GLOBAL_LOG_FUNCTION`. A target that links the
  library must not define it again — `keystore_server` routes its own logging through this definition
  for that reason (comment at the top of `keystoreServer.cpp`).
- **Link**: `target_link_libraries(<target> PRIVATE keystore)`; RocksDB and `wazuhext` come with it.
  `indexer_connector` also finds it through `link_directories(${SHARED_MODULES}/keystore/build)`, which
  is the standalone build `.github/actions/build_external_deps` produces for CI.

## Layout

```
keystore/
├── CMakeLists.txt              # libkeystore.a; wazuh-manager-keystore unless UNIT_TEST; tests under UNIT_TEST; testtool always
├── COPYING                     # GPL-2.0-only OR AGPL-3.0-or-later
├── include/keyStore.hpp        # Keystore::put/get, KeystoreLockTimeout, the two lock waits
├── src/keyStore.cpp            # encryption, per-operation open, version stamp
├── src/main.cpp                # wazuh-manager-keystore: input handling, home, privilege drop, -g
├── src/argsParser.hpp          # -f -k -v -vp -g -h
├── tests/component/            # keystore_ctests (GTest, real RocksDB in ./queue/keystore)
├── qa/test_keystore.py         # pytest over the CLI and the testtool
└── testtool/                   # wazuh-keystore-testtool: -c <family> -k <key> [-v <value>]
```

The CLI is installed `root:root` 0750 by `InstallServer` (`src/init/inst-functions.sh`), which also
creates `queue/keystore` (`wazuh-manager` 0750); both rows are pinned by
`.github/actions/check_files/manager_base.csv`. `wazuh-keystore-testtool` is a build-tree tool only: it
reads with `-c` (not `-f`) when no value is given, uses the default lock wait, opens `queue/keystore`
relative to its working directory and never drops privileges.

## Tests

| Suite | Covers | CI lane |
|---|---|---|
| `tests/component/keyStoreComponent_test.cpp` (`keystore_ctests`, ctest label `keystore_ctests`) | RF-1 – RF-6: put/get, the version stamp, no family on read, waiting for another handle, concurrent threads, the lock timeout that writes nothing, the caller's wait, the two waits' order | [`5_testcomponent_keystore.yml`](../../../.github/workflows/5_testcomponent_keystore.yml): a plain leg (named `valgrind`, runs no valgrind) and an ASAN leg, `allowed_skips: 0` |
| `qa/test_keystore.py` | RF-7 – RF-9 over the real CLI binary, read back through the testtool | [`5_testintegration_keystore.yml`](../../../.github/workflows/5_testintegration_keystore.yml): builds the CLI with `-DUNIT_TEST=OFF`, symlinks both binaries into `src/`, sets `WAZUH_MANAGER_HOME` to `src/`, fails on any skip |
| `src/init/credentials/tests/` | the resolver's use of the CLI, against a **stub** `wazuh-manager-keystore` (`KEYSTORE_STUB` in `conftest.py`) — the real binary's exit codes are pinned only by `qa/` | `5_testunit_credentials.yml` |
| `test_manager_control/` (whole-manager integration) | the installed CLI as the resolver runs it at every start | selected by `src/**` in `.github/test_modules_manager.json`, from `5_builderpackage_manager-multiples.yml` |

Also: [`5_codelinter_clangformat.yml`](../../../.github/workflows/5_codelinter_clangformat.yml) checks
the `.cpp`/`.hpp` files here, and [`5_codequality_spdx.yml`](../../../.github/workflows/5_codequality_spdx.yml)
their SPDX lines. RF-10 (home and privilege drop) and RF-11 (the busy message) have no test.

To reproduce the component suite locally:

```bash
cmake -S src -B src/build -DUNIT_TEST=ON
cmake --build src/build -j --target keystore_ctests
ctest --test-dir src/build -L keystore_ctests --output-on-failure
```

The suite deletes and recreates `queue/keystore` in its working directory. The `qa/` suite needs a
`UNIT_TEST=OFF` tree (the CLI target does not exist otherwise); the workflow's last step is the exact
recipe.

## License

Dual-licensed under `GPL-2.0-only OR AGPL-3.0-or-later`. See [COPYING](COPYING).
