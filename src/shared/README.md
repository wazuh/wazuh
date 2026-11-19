# shared (libwazuh)

The C support library every Wazuh C program links: logging, files and paths, privilege drop,
threads, queues, sockets, crypto, XML/regex/zlib, the wazuh-db and Task Manager clients, the
cluster getters, x509 and enrollment-token helpers, and the numbered message catalogue. It is built
for **every** `TARGET` — manager, agent and Windows agent — so a change here can red the agent
lanes as well as the manager's.

Two documentation layers cover it:

- **This README** — what lives here, what links it, which parts are manager-only, and the
  invariants other components depend on: the [log format](#logging-debug_op) the engine copies,
  the [home resolution](#home-resolution-w_homedir) the engine copies, the
  [Task Manager ids](#task-manager-producer-manager_task_op) the task manager re-derives, and
  [log rotation](#log-rotation-log_rotate).
- **Operator pages** for the behaviour these produce — the line formats, `log_format` and the
  rotated layout in [`docs/ref/modules/logging/`](../../docs/ref/modules/logging/README.md), the
  rotation schedule in
  [Recurring manager tasks](../../docs/ref/modules/task_manager/schedules.md). This file links them
  and does not restate them.

## Requirements

### Functional (RF)

| # | Requirement | Where it is answered |
|---|---|---|
| RF-1 | Write every C daemon's log lines, plain and/or JSON, to `logs/wazuh-manager.log`/`.json` (manager) or `logs/ossec.log`/`.json` (agent), relative to the working directory | `src/debug_op.c`, `LOGFILE`/`LOGJSONFILE` in `include/debug_op.h` |
| RF-2 | Read the log format of a manager daemon from the effective `wazuh-manager.conf` without linking the configuration library | `os_logging_config()` (`#ifndef CLIENT` branch) through `w_mconf_hook_section()` (`src/mconf_hook.c`) |
| RF-3 | Resolve the installation home of a daemon | `w_homedir()` (`src/file_op.c`) |
| RF-4 | Rotate the internal log files daily and by size into the dated archive layout, optionally gzip-compressed, removing archives past the retention | `w_rotate_log()` (`src/log_rotate.c`) |
| RF-5 | Create, count and read Task Manager rows over `queue/sockets/task-http.sock`, with deterministic ids for the producers that may run twice | `src/manager_task_op.c` |
| RF-6 | Answer the node role, node name and cluster name from the effective configuration | `w_is_worker()`, `w_is_single_node()`, `get_node_name()`, `get_cluster_name()` (`src/cluster_utils.c`), through the same hook |
| RF-7 | Query wazuh-db over `queue/sockets/wdb.sock`, and wrap its global-database commands | `src/wazuhdb_op.c`, `src/wazuhdb_queries_op.c` |
| RF-8 | Encode, decode and derive keys for enrollment tokens and re-enrollment secrets | `src/enrollment_token.c` — consumers in `os_auth/src/` and `client-agent/src/` |
| RF-9 | Open a file without following a link, writing only a lone regular file | `w_openat_nofollow_vetted()` (`src/file_op.c`) |
| RF-10 | HTTP over a Unix socket for the manager's internal HTTP servers | `uhttp_*` (`src/http_op.c`) |
| RF-11 | Hold every numbered diagnostic (`(NNNN): ...`) in one place | `include/error_messages/` |

### Non-functional (RNF)

| # | Requirement | Where it is answered |
|---|---|---|
| RNF-1 | One source tree for three targets: manager-only code compiles out of agent builds | `#ifndef CLIENT` (`CLIENT` is defined for agent targets in [`src/CMakeLists.txt`](../CMakeLists.txt)); the Windows build drops `batch_queue_op.c`, `http_op.c` and `indexed_queue_op.c` ([`CMakeLists.txt`](CMakeLists.txt)) |
| RNF-2 | No dependency on the configuration library or `manager_config` | the hook in `include/mconf_hook.h` — D1 |
| RNF-3 | A log line is never written through a link an unprivileged account planted | `open_log_file()` (`src/debug_op.c`) — D2 |
| RNF-4 | The library is unit-testable with its dependencies mocked | `libwazuh_test.a`, the same sources plus `src/unit_tests/wrappers/` and `WAZUH_UNIT_TESTING` ([Tests](#tests)) |

## Layout

| Path | Contents |
|---|---|
| `src/`, `include/` | the library proper, one `*_op.c` / `*_op.h` pair per area (table below); `include/shared.h` is the umbrella header, `include/defs.h` the paths, sockets, user and group defaults |
| `include/error_messages/` | `error_messages.h`, `warning_messages.h`, `information_messages.h`, `debug_messages.h`: the numbered message macros (`HOME_ERROR` is `(1108)`, for example) |
| `os_crypto/` | hashes (`md5`, `sha1`, `sha256`, `sha512`, `md5_sha1_sha256`, `hmac`), ciphers (`aes`, `blowfish`), `signature/` (WPK signature checks) and `shared/`: `keys.c` (the `client.keys` keystore, `OS_ReadKeys()`, the IP tree authd and remoted use) and `msgs.c` (the legacy channel's message encryption and counters) |
| `os_net/` | sockets: TCP/UDP bind and connect, Unix sockets, the length-prefixed `OS_SendSecureTCP()`/`OS_RecvSecureTCP()` |
| `os_xml/` | the XML reader the agent's `ossec.conf` and the shared `agent.conf` use (the manager's own configuration is read by [`manager_config`](../shared_modules/manager_config/README.md)) |
| `os_regex/`, `os_zlib/` | the OS_Regex/OS_Match engine; zlib compression helpers |

Also compiled in: `src/active-response/src/active_responses.c`, for the execd and active-response
binaries. There is no README for the subdirectories; read the headers.

### What the areas are

| Area | Files (`src/` + `include/`) | Manager, agent or both |
|---|---|---|
| Logging | `debug_op`, `logging_helper`, `log_rotate`, `compress_log` | both; `os_logging_config()` and the rotation paths differ by `CLIENT` |
| Files, paths, home | `file_op`, `fs_op`, `store_op`, `binaries_op` | both (`w_homedir()` is outside `WIN32`) |
| Process and threads | `privsep_op`, `pthreads_op`, `sig_op`, `exec_op`, `wait_op`, `rwlock_op`, `atomic`, `startup_gate_op` | both; the startup gate is a no-op on the manager |
| Containers and queues | `list_op`, `queue_op`, `queue_linked_op`, `bqueue_op`, `indexed_queue_op`, `batch_queue_op`, `hash_op`, `hashmap_op`, `rbtree_op`, `vector_op`, `buffer_op` | both (the indexed and batch queues are not built for Windows) |
| Strings and data | `string_op`, `utf8_op`, `utf8_winapi_wrapper`, `json_op`, `yaml2json`, `b64`, `b64url_op`, `expression`, `regex_op`, `custom_output_search_replace`, `math_op`, `mem_op`, `time_op`, `version_op`, `validate_op`, `labels_op` | both |
| Configuration hook and cluster | `mconf_hook`, `cluster_utils` | manager (`#ifndef CLIENT`) |
| Manager clients | `wazuhdb_op`, `wazuhdb_queries_op`, `manager_task_op`, `auth_client`, `http_op` | built everywhere; called by manager code (`auth_client.c` is fenced by `CLIENT`) |
| Agents, keys, enrollment | `agent_op`, `agent_validate_op`, `enrollment_token`, `read-agents`, `remoted_op`, `request_op`, `module_limits`, `module_report`, `notify_op`, `sysinfo_utils` | both |
| TLS and certificates | `ssl_op`, `check_cert_op`, `x509_op`, `os_cert_bundle`, `cryptography`, `randombytes` | both |
| Agent subsystems | `syscheck_op`, `audit_op`, `schedule_scan`, `agentd_query`, `log_builder`, `read-alert`, `url`, `mq_op`, `sym_load`, `dll_load_notify`, `bzip2_op`, `os_utils`, `help` | mostly agent; several are also called by manager code (grep before assuming) |

Being compiled for the manager does not make a file manager-reachable, and a file with no
`CLIENT` guard is not necessarily used by the agent: check the callers.

## Build and consumers

[`CMakeLists.txt`](CMakeLists.txt) globs `src/*.c` and every subdirectory above into one static
library, `wazuh` (`libwazuh.a`, `POSITION_INDEPENDENT_CODE`, output hard-coded to
`src/build/lib`), linked `PUBLIC` against `wazuhext`. With `UNIT_TEST` it also builds
`wazuh_test` (`libwazuh_test.a`): the same sources plus every wrapper under
`src/unit_tests/wrappers/`, compiled with `WAZUH_UNIT_TESTING`, `-g -O0` and coverage. The library
is compiled with `ARGV0="wazuh"`, but a log line's tag is the caller's: each daemon calls
`OS_SetName(ARGV0)` and the logger reads that name at run time.

| Consumer | Links `wazuh` through |
|---|---|
| `wazuh-manager-remoted` | `remoted_lib` ([`src/remoted/`](../remoted/README.md)) |
| `wazuh-manager-authd` | `authd_lib` ([`src/os_auth/`](../os_auth/README.md)) |
| `wazuh-manager-db` | `wdb_lib` ([`src/wazuh_db/`](../wazuh_db/)) |
| `wazuh-manager-modulesd` and the module shims | [`src/wazuh_modules/CMakeLists.txt`](../wazuh_modules/CMakeLists.txt) |
| every user of libconfig | `config` links `wazuh` `PUBLIC` ([`src/config/`](../config/README.md)) |
| `verify-agent-conf` | [`src/util/CMakeLists.txt`](../util/CMakeLists.txt) |
| the agent daemons, active responses and Windows tools | their own CMake projects |

**The engine does not link it.** `wazuh-manager-analysisd` re-implements the pieces it shares with
the C daemons — the log sink and the home resolution — so those are
[duplicates kept by hand](#duplicates-kept-by-hand).

## Logging (`debug_op`)

`m{debug1,debug2,info,warn,error}()` and their `mt*` (tagged), `plain_*` and `*_exit` variants
all reach `_log_function()`:

- The **format** (plain, JSON or both) is read once by `w_logging_init()` → `os_logging_config()`.
  On a manager it comes from the `logging` section through the configuration hook, defaulting to
  plain with no provider or no document; on an agent `ossec.conf` is parsed directly. The line
  shapes and the debug prefix are the operator contract in
  [Logging configuration](../../docs/ref/modules/logging/configuration.md).
- **Each line opens the file again** (`O_APPEND`), so a rename by the rotation is picked up by the
  next line. `open_log_file()` opens it relative to its directory with
  `w_openat_nofollow_vetted()`: a symlink, hard link or FIFO at the name drops the line, with one
  warning to stderr per process (D2).
- A file this call creates gets mode `0660` exactly (`fchmod`), and, when running as root, group
  `GROUPGLOBAL` (`fchown`), both through the descriptor.
- Lines are written under one process-wide mutex; outside daemon mode they are also printed to
  stderr.
- `mtLoggingFunctionsWrapper()` is the callback C++ modules receive to log through this writer
  (remoted passes it to `remoted_module_start()`).

## Configuration hook (`mconf_hook`)

`w_mconf_hook_set()` registers a section provider; `w_mconf_hook_section()` asks it for a section of
the effective document (caller frees) and returns `NULL` without a provider. libconfig registers the
provider when it loads the document (`src/config/src/mconf-config.c`); the readers inside libwazuh
— the cluster getters (`src/cluster_utils.c`) and the log format (`src/debug_op.c`) — go through
it. Unit tests register their own (`test_cluster_utils`, `test_logging_config`). Manager only.

## Home resolution (`w_homedir`)

`w_homedir()` returns, in order: on the manager only, `WAZUH_MANAGER_FORCE_HOME` when defined —
even empty — as is and **never checked** (`WAZUH_MANAGER_FORCE_HOME_ENV`, `include/file_op.h`; the
same rule as the engine's `resolveManagerHome()`); the `WAZUH_HOME_ENV` variable when non-empty
(`WAZUH_MANAGER_HOME` on the manager, `WAZUH_AGENT_HOME` on an agent — `include/defs.h`), else the
directory of `/proc/self/exe` (then `/proc/curproc/file`, `/proc/self/path/a.out`, `argv[0]`; on
macOS `proc_pidpath()`) cut at `/bin`. A result of those last two steps that is not a directory exits
with `HOME_ERROR` (1108). The daemons `chdir()` there; every relative path afterwards (`LOGFILE`,
`queue/sockets/*`) is relative to it.

The configuration directory is not the home: `WAZUH_MANAGER_CONF_DIR` (`/etc/wazuh-manager`, fixed,
`include/defs.h`) roots `client.keys`, `authd.pass`, `shared/`, the internal options file and the
other `/etc/wazuh-manager` paths.

## Task Manager producer (`manager_task_op`)

The client authd and the vulnerability scanner use to record work that must outlive the process
that asked for it (`manager_task_create()`, `manager_task_count()` and the other calls in
`include/manager_task_op.h`; operator side in
[`docs/ref/modules/task_manager/`](../../docs/ref/modules/task_manager/README.md)).

- **Ids are SHA-256, 64 lowercase hex characters**, over one of three recipes:
  `mt:del:<agent_id>:<journal_seq>` (`manager_task_id_agent_delete()`),
  `mt:sched:<schedule_id>:<scheduled_run_at>` (`manager_task_id_schedule()`) and
  `mt:<tag>:<32 random hex>` (`manager_task_id_random()`). The first two make a creator that runs
  twice for one logical event idempotent — authd replays its deletion journal at every start, and a
  schedule's spawn loop has no transaction across "insert the row" and "advance `next_run_at`".
- The scheduled recipe is also computed by the task manager itself, in C++
  (`forScheduledRun()` in `src/wazuh_modules/task_manager/src/model/taskId.cpp`); the two must match
  byte for byte. Both sides assert the same golden vector,
  `SHA-256("mt:sched:agent_delete_old:1700000000")` = `6b74b099…ad623`
  (`src/unit_tests/shared/test_manager_task_op.c`,
  `src/wazuh_modules/task_manager/test/unit/schedule_test.cpp`); the deletion recipe is pinned only
  on this side.
- **One HTTP client per call** over `WM_TASK_MODULE_SOCK`, with a 2 s connect deadline separate from
  the caller's round-trip timeout, and an **absolute** URL (`WM_TASK_MODULE_URL` + route).
- A non-2xx answer is still parsed: a refused creation names why in `result` (`created`,
  `coalesced`, `collided`, `queue_full`).

## Log rotation (`log_rotate`)

`w_rotate_log(compress, keep_log_days, new_day, rotate_json, daily_rotations)` moves `LOGFILE`
and/or `LOGJSONFILE` into `logs/wazuh/<YYYY>/<Mon>/<prefix>-<DD>[-<NNN>].{log,json}` — prefix
`wazuh` on the manager, `ossec` on an agent — compresses the result when asked, and removes
archives older than `keep_log_days`. The resulting layout is documented for operators in
[Logging — Rotation](../../docs/ref/modules/logging/configuration.md).

- A daily rotation names the archive after the previous day and rotates both files in one pass; a
  size rotation rotates the one named by `rotate_json`.
- When the day already holds `daily_rotations` archives, the slots are shifted down and the oldest
  is overwritten; whether a slot holds `.gz` or plain text is decided per slot.
- An empty JSON log is not archived, and the JSON slot counter starts from zero rather than from
  the `.log` branch's count (D4).
- A failed `mkdir` of the year or month directory aborts that rotation only (D3).

Callers: on the manager, the task manager's host callbacks in `src/wazuh_modules/src/wm_task_manager.c`
(daily and size-based, inside **modulesd**); on an agent, `w_rotate_log_thread()` in
`src/client-agent/src/rotate_log.c`.

## Invariants

1. **Nothing here may depend on libconfig or `manager_config`** — libconfig itself links this
   library. A new configuration reader inside libwazuh asks through the hook (D1).
2. **Manager-only code is fenced by `#ifndef CLIENT`** (or kept out of the agent's link by its
   callers), and Windows-incompatible files are listed in `CMakeLists.txt`. The agent and winagent
   unit-test legs build this directory, so a manager-only change that leaks reds them.
3. **The enrollment-token derivation is the C++ one, byte for byte.** `src/enrollment_token.c`
   replicates the HKDF of `src/shared_modules/utils/jwt/enrollKeyDerivation.hpp` (labels
   `WAZUH-ENROLL-TOKEN-KEY`, `WAZUH-REENROLL-KEY`); `W_REENROLL_SECRET_BYTES` is tied to
   `AGENT_REENROLL_SECRET_BYTES` by a `_Static_assert`. `W_ETOKEN_DEFAULT_PORT` (1517) is the port a
   token's `adr` omits — part of the token encoding, not the listener's configured port.
4. **`W_ETOKEN_STORE_MAX_BYTES` stays below remoted's replica ceiling** (`TokenKeySource::kMaxStoreBytes`,
   8 MiB): above it the replica keeps a stale store and only counts a reload failure (comment in
   `include/enrollment_token.h`).

### Duplicates kept by hand

| Here | Must match | Detected by |
|---|---|---|
| line format of `src/debug_op.c` (timestamp, tag, debug prefix, level names, JSON keys) and the file rules of `open_log_file()` | `src/engine/source/base/src/managerLogSink.cpp` ([base README — Manager Log Sink](../engine/source/base/README.md#manager-log-sink)) | nothing — each side has its own tests |
| `w_homedir()` | `resolveManagerHome()` in `src/engine/source/base/src/process.cpp` ([base README — Process Helpers](../engine/source/base/README.md#process-helpers)) | nothing |
| `WAZUH_MANAGER_CONF_DIR` (`include/defs.h`) | `Utils::MANAGER_CONF_DIR` (`src/shared_modules/utils/managerConfDir.hpp`), the engine's `base/managerConfig.hpp`, `CONF_PATH` in `framework/wazuh/core/common.py`, `CONF_DIR` in `src/init/shared.sh` and the resolver | only the resolver's and `common.py`'s are test-pinned |
| socket constants in `include/defs.h` | `framework/wazuh/core/common.py` (the sets differ by design, and neither is complete) | nothing |
| `mt:sched:` recipe in `src/manager_task_op.c` | `taskId.cpp` `forScheduledRun()` | the shared golden vector |
| enrollment / re-enrollment key derivation | `enrollKeyDerivation.hpp`; the frozen vectors in `src/unit_tests/shared/test_enrollment_token.c` are copied from `src/shared_modules/utils/jwt/testVectors.hpp` | each side's own assertions |

## Design decisions (D1–D7)

| # | Decision | Rationale (where it is recorded) |
|---|---|---|
| D1 | **libwazuh reads manager configuration through a registered provider, not by calling libconfig** | libwazuh cannot depend on libconfig/`manager_config`; without a provider (agent binaries, unit tests) every lookup returns `NULL` and callers keep their no-configuration behaviour (`include/mconf_hook.h`) |
| D2 | **The log file is opened per line, relative to its directory, without following links, and only a lone regular file is written**; a created file gets its mode and group through the descriptor | `logs/` is writable by the service account, so the name may be a link, hard link or FIFO that account planted, and a daemon logs as root until it drops privileges (comment on `open_log_file()`) |
| D3 | **A failed directory creation aborts the rotation, not the process** | It used to `merror_exit()`, survivable while rotation lived in its own daemon; inside a modulesd module an unwritable log directory would take all of modulesd down (comment in `w_rotate_log()`) |
| D4 | **An empty JSON log is not archived, and the JSON slot counter is independent** | The empty file (the install placeholder under plain logging) has nothing to archive; carrying the `.log` counter over skipped JSON slots when the two counts differed (comments in `w_rotate_log()`) |
| D5 | **Task Manager ids for re-runnable producers are deterministic and pinned by golden vectors** | A refactor that still hashed something consistently would keep every round-trip test green and silently break idempotency (comment in `test_manager_task_op.c`) |
| D6 | **The Task Manager client opens one connection per call and uses an absolute URL** | The task manager answers one request per connection; a cached handle would save microseconds against making the call thread-safe for authd. libcurl needs an absolute URL — a bare path fails with no HTTP status, indistinguishable from an outage (comments in `manager_task_request()`) |
| D7 | **`w_homedir()` reads `WAZUH_MANAGER_FORCE_HOME` first on the manager, as is and unchecked, like the engine** | One variable must relocate every manager daemon into the same tree; remoted applied it privately (ignoring an empty value) and no other C daemon read it. The engine's rule wins where they differed: a defined but empty value is the home, and a forced home skips the directory check (comment on `w_homedir()`) |

## Tests

| Suite | Scope | Runs in |
|---|---|---|
| `src/unit_tests/shared/` (cmocka, one `test_<area>.c` per area) | the library, linked against `libwazuh_test.a` with `--wrap` mocks ([`src/unit_tests/shared/CMakeLists.txt`](../unit_tests/shared/CMakeLists.txt)). Manager-only suites include `test_manager_task_op`, `test_cluster_utils`, `test_logging_config`, `test_schedule_scan`, `test_fs_op`, `test_wazuhdb_op`, `test_wazuhdb_queries_op`, `test_bqueue`; `test_log_rotate` runs for every target but `winagent` | every leg (manager, agent, winagent) of [`5_testunit_linux-win.yml`](../../.github/workflows/5_testunit_linux-win.yml), and [`5_testunit_macos.yml`](../../.github/workflows/5_testunit_macos.yml); coverage reported, not gated |
| `src/unit_tests/os_crypto/`, `os_net/`, `os_regex/`, `os_xml/`, `os_zlib/` | the subdirectories (`os_crypto/shared` only in the manager leg) | the same workflows |
| Static analysis | the whole tree | [`5_codeanalysis_scanbuild.yml`](../../.github/workflows/5_codeanalysis_scanbuild.yml) |
| Whole manager | `wazuh_db`, `remoted-tier-0-1`, `remoted-tier-2` and `authd-tier-0-1` of [`test_modules_manager.json`](../../.github/test_modules_manager.json) list `src/shared/**` | [`5_builderpackage_manager-multiples.yml`](../../.github/workflows/5_builderpackage_manager-multiples.yml) |

The engine side of the hand-kept pairs is tested in the engine lane
([`5_testunit_engine.yml`](../../.github/workflows/5_testunit_engine.yml), e.g.
`managerLogSink_test.cpp`), and the task manager's `schedule_test.cpp` in
[`5_testunit_taskmanager.yml`](../../.github/workflows/5_testunit_taskmanager.yml). How to run each
lane locally is in the `wazuh-testing` skill.
