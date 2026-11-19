# common — shared C/C++ definitions of the manager and the agent

Two headers, no code to compile and **no `CMakeLists.txt`**: nothing builds here and nothing links
anything from here. The directory is only an include path —
`include_directories(${SRC_FOLDER}/shared_modules/common)` in `src/CMakeLists.txt` covers the whole tree
(the engine included), and many consumer `CMakeLists.txt` files repeat it (remoted, modulesd's
`wazuh_modules/CMakeLists.txt`, remoted_module, inventory_sync_server, task_manager, keystore_server, the
agent's client-agent, https_client, data_provider, syscheckd, rootcheck, SCA, syscollector, agent_info,
win32, `src/unit_tests`).

| Header | Language | Content |
|---|---|---|
| `commonDefs.h` | C, included from C++ | Types shared across the C/C++ boundary (below) |
| `httpsHeaderLine.hpp` | C++ | `HTTPS_HEADER_LINE_JSON_MAX_BYTES` (8 KiB): the size limit of the JSON in the `H` line that opens every `/stateless` body |

There is no operator page for this directory: neither header carries anything an operator configures or
observes. The behaviour behind `HTTPS_HEADER_LINE_JSON_MAX_BYTES` is documented with the endpoint on the
[HTTPS agent API](../../../docs/ref/modules/remoted/https-events-api.md) page.

## Requirements

| # | Requirement | Where |
|---|---|---|
| RF-1 | `commonDefs.h` defines the C types every C-ABI module shares: the logging callbacks `log_fnc_t` and `full_log_fnc_t` (level, tag, file, line, function, message, `va_list`) that the modulesd/remoted modules take in their start functions; `HostType` (`MANAGER`, `AGENT`); the dbsync vocabulary (`DbEngineType`, `DbManagement`, `ReturnTypeCallback`, `DBSYNC_HANDLE`, `TXN_HANDLE`, `result_callback_t`, `sync_id_callback_t`, `callback_data_t`, `sync_callback_data_t`); `UNLIMITED_QUEUE_SIZE` | `commonDefs.h` |
| RF-2 | `httpsHeaderLine.hpp` is the single definition of the `/stateless` `H`-line JSON limit: remoted rejects a larger one together with the whole batch, and the agent trims its `H` line to fit | `httpsHeaderLine.hpp`; read by `src/remoted/remoted_module/src/endpoints/statelessEndpoint.cpp` and `src/client-agent/https_client/src/statelessStream.cpp` |
| RNF-1 | `commonDefs.h` stays valid C (it is included by C sources such as `src/wazuh_modules/src/wm_syscollector.c` and `src/syscheckd/include/syscheck.h`) and includes `cJSON.h` and `<stdarg.h>`, so a consumer needs cJSON on its include path | `commonDefs.h` |
| RNF-2 | Dual-licensed `GPL-2.0-only OR AGPL-3.0-or-later` (the directory is in the SPDX scope): every source file needs that SPDX line in its first 30 lines; this README needs none | `.github/scripts/spdx_scope.py`, [COPYING](COPYING) |

## Consumers of `commonDefs.h`

On the manager: the module C ABIs that take a `full_log_fnc_t` (`content_manager.h` — under `src/shared_modules/content_manager/include/` — `task_manager.h`,
`inventory_sync_server.h`, `keystore_server.h`, `vulnerability_scanner.h`, `remoted_module.h`,
`src/wazuh_db/src/http/wdb_http.h`), the engine's `src/engine/source/base/include/base/logging.hpp`,
`indexer_connector`'s bulk queue, and several headers of [utils](../utils/README.md) (`loggerHelper.h`,
`msgDispatcher.h`, `threadDispatcher.h`, `threadEventDispatcher.hpp`, `filterMsgDispatcher.hpp`,
`asyncValueDispatcher.hpp`), which drag it into every module that includes them. On the agent: dbsync,
data_provider (`sysInfo.h`), syscheckd, syscollector, SCA, agent_info and https_client.

A change to either header therefore recompiles — and can break — both products.

## Design decisions

| # | Decision | Why |
|---|---|---|
| D1 | The `H`-line limit lives in one header read by both remoted and the agent | The agent used to trim its `H` line to a copy of remoted's limit; had the two drifted, every batch from an agent with a long group list would have been rejected (commit that introduced `httpsHeaderLine.hpp`) |
| D2 | Dual licence `GPL-2.0-only OR AGPL-3.0-or-later` | The headers are included both by the AGPLv3 engine and by GPLv2-only code; [utils](../utils/README.md#design-decisions) (D11) records the same reason for the libraries the engine links |

## Tests and CI

Nothing here has a test of its own. The headers are compiled by their consumers' lanes, which list them
in their `paths:`:

| Lane | Selects |
|---|---|
| `.github/workflows/5_testcomponent_remoted_module.yml` | `src/shared_modules/common/**` |
| `.github/workflows/5_testcomponent_https_client-rtr.yml` | `src/shared_modules/common/**` (but not `COPYING`) |
| `.github/workflows/5_testunit_shared_modules_utils.yml` | `commonDefs.h` |
| `.github/workflows/5_testunit_uds_http_server.yml` | `commonDefs.h` |

`HTTPS_HEADER_LINE_JSON_MAX_BYTES` is asserted on the agent side by
`src/client-agent/https_client/tests/unit/statelessStream_test.cpp` (the trimmed `H` line fits the limit);
on the manager side remoted applies it as `kMaxHeaderLineJsonSize` in `statelessEndpoint.cpp`.

## License

Dual-licensed under `GPL-2.0-only OR AGPL-3.0-or-later`; see [COPYING](COPYING).
