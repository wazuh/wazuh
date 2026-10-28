# Base Module

## Overview

The **base** module is a static library (`base`, see [CMakeLists.txt](CMakeLists.txt)) with the common utilities of the Wazuh Engine: JSON, graphs, expressions, logging, process helpers, the manager configuration loader and small string/IP/time utilities. Every other engine module links against it.

This README covers in depth only two pieces that carry operational contracts: the **manager log sink** (the writer behind `logs/wazuh-manager.log` and `logs/wazuh-manager.json` in manager mode) and the **process helpers** (daemonization, PID file, user/group lookup and privilege drop, manager home). The rest is listed in the directory structure below; read the headers for their API.

## Directory Structure

```
base/
├── CMakeLists.txt
├── README.md
├── include/base/
│   ├── json.hpp                # base::json::Json, the JSON document type used across the engine
│   ├── graph.hpp               # Graph type
│   ├── expression.hpp          # Expression and formula types
│   ├── eventParser.hpp         # Event parser
│   ├── logging.hpp             # Logging front-end (LOG_* macros, standalone and manager mode)
│   ├── managerLogSink.hpp      # Manager-mode log writer (see "Manager Log Sink")
│   ├── process.hpp             # Process helpers (see "Process Helpers")
│   ├── managerConfig.hpp       # Process-wide read access to the manager configuration (manager mode)
│   ├── dailyRotatingFileSink.hpp  # Daily rotating file sink (used by logging.cpp)
│   ├── error.hpp, result.hpp   # Error and result types
│   ├── name.hpp, dotPath.hpp   # Asset names and dotted paths
│   ├── timer.hpp, syncStatus.hpp, statusSnapshot.hpp, ymlFormat.hpp, baseTypes.hpp
│   └── utils/                  # stringUtils, ipUtils, timeUtils, communityId, singletonLocator, ...
├── src/                        # Implementations (managerLogSink.cpp, process.cpp, logging.cpp, ...)
├── test/include/               # base::test INTERFACE include directory (test helpers)
├── test/src/unit/              # GoogleTest unit tests
└── benchmark/                  # base_benchmark (eventParser, json)
```

## Manager Log Sink

Header: [include/base/managerLogSink.hpp](include/base/managerLogSink.hpp). Implementation: [src/managerLogSink.cpp](src/managerLogSink.cpp).

In manager mode the engine writes `logs/wazuh-manager.log` and `logs/wazuh-manager.json`, relative to the current directory (the manager home after `main()`'s `chdir`). The lines are the same plain and JSON lines the C logger produces, and the destinations are written in the order JSON, plain, stderr.

Behaviour:

- **One `write()` per destination.** Each line is composed in memory and written with a single `write()` per destination, under one process-wide mutex. A short write drops the rest of that line; it is not retried.
- **Files opened per line with `O_APPEND`.** A rotation (rename) of the file is picked up by the next line.
- **New files.** Created with mode 0660. The group is set to `wazuh-manager` (via `base::process::lookupGid`) only when running as root; if the lookup fails, the file keeps the group of its creator. A failing `fchmod` or `fchown` does not prevent the line from being written.
- **Never throws, preserves `errno`.** The caller's `errno` is restored after every call.
- **No-op before `initManager()`.** Unit tests and `main()` before the call write nothing and touch no file.
- **Immortal state.** The options, dependencies and mutex are allocated once and never destroyed, so late lines (exit handlers, late threads) never touch a destroyed mutex.
- **Fork safety.** The mutex crosses the `fork()` calls of `goDaemon()` only because, in manager mode, no other thread exists yet: `main.cpp` calls `initManager()` before `goDaemon()`.
- **Injection.** `ManagerLogDeps` holds the system calls (`open`, `write`, `fchown`, ...) and clock/pid/root/group lookups; an empty member means the real call.

## Process Helpers

Header: [include/base/process.hpp](include/base/process.hpp). Implementation: [src/process.cpp](src/process.cpp).

| Function | Behaviour |
|---|---|
| `goDaemon` | fork, `setsid`, fork, `umask(027)`, stdin/stdout/stderr redirected to `/dev/null`. The parents leave with a real `_exit` (no exit handlers). |
| `createPID` | Writes `<path>/<name>-<pid>.pid` with mode exactly 0640 (`fchmod`) and content `<pid>\n`; retries on `EINTR` and completes partial writes. |
| `lookupUid` / `lookupGid` | Reentrant lookups. The buffer starts at the `sysconf` hint (1024 when undefined, capped at 64 KiB) and doubles up to 64 KiB. |
| `dropToGroup` | `setgroups` + `setgid`. Call it before `dropToUser`. |
| `dropToUser` | `setuid` + `seteuid`. Irreversible when leaving root. |
| `resolveManagerHome` | Order: `WAZUH_MANAGER_FORCE_HOME` as is, then a non-empty `WAZUH_MANAGER_HOME`, then the dirname of `/proc/self/exe` cut at the first `"/bin"`. When the result of the 2nd or 3rd is not a directory it writes a CRITICAL 1108 line to stderr and exits with status 1. |
| `setManagerMode` / `getWazuhHome` | Manager mode is process-wide and irreversible. Outside it, `getWazuhHome()` returns the current working directory. |

Injection: `ProcessSysCalls` groups 13 system calls (`fork`, `setsid`, `umask`, `open`, `dup2`, `close`, `fchmod`, `write`, `setgroups`, `setgid`, `setuid`, `seteuid`, `sysconf`); an empty member is the real call. Outside the seam is `_exit` (checked by `GoDaemonFunctionalTest.ParentsSkipExitHandlers`); `umask` is injectable, but a test that leaves it empty gets the real `umask(027)` applied to itself. `UserLookup` and `GroupLookup` are injectable as well.

## Time Utilities

Header: [include/base/utils/timeUtils.hpp](include/base/utils/timeUtils.hpp). Implementation: [src/utils/timeUtils.cpp](src/utils/timeUtils.cpp). Namespace `base::utils::time`.

The reception timestamp of an event comes from a process-wide clock whose values never repeat and never go back, so events ingested in this process get distinct, ordered timestamps even when the wall clock ties or steps backwards. The price of a backward step of Δ is that stamps run ahead of the wall clock for up to Δ, advancing one nanosecond per event; a restart or another node starts its own sequence.

| Function | Behaviour |
|---|---|
| `systemEpochNanos` | `int64_t`, nanoseconds since the epoch read from `std::chrono::system_clock` (wall clock, not monotonic). `noexcept`. |
| `StrictlyIncreasingClock::next(now)` | Returns `max(now, last + 1)`, published with a CAS loop over a `std::atomic<int64_t>`: it never repeats or goes back and is safe from any number of threads. `now` defaults to `systemEpochNanos()`; only tests inject it. `noexcept`. |
| `receptionClock` | The `StrictlyIncreasingClock` (function-local static) shared by every ingest thread. |
| `epochNanosToISO8601` | Formats nanoseconds as `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`: UTC, always 9 fraction digits, reentrant (`gmtime_r`), no `date` library. Negative values floor to the previous second. |

`getCurrentISO8601()` is unchanged (millisecond precision, used elsewhere).

Consumers: the `api/event` NDJSON parser (`ndJsonParser.hpp`) stamps `receivedAtNs` with `receptionClock().next()`; the `router` `RouterWorker` uses that value, or `receptionClock().next()` when it is 0, and `TesterWorker` calls `receptionClock().next()`; both format it with `epochNanosToISO8601`.

Tests: `TimeUtilsTest.StrictClock*`, `TimeUtilsTest.EpochNanosToISO8601*` and `TimeUtilsTest.ReceptionClockIsSharedAndIncreasing` in [timeUtils_test.cpp](test/src/unit/utils/timeUtils_test.cpp) (run in `base_utest`).

## Testing

Three binaries are built with `ENGINE_TEST=y` (see [CMakeLists.txt](CMakeLists.txt)):

| Binary | Content |
|---|---|
| `base_utest` | The files listed in [CMakeLists.txt](CMakeLists.txt): `test/src/unit/*_test.cpp` and `test/src/unit/utils/*_test.cpp` except the two below, including [process_test.cpp](test/src/unit/process_test.cpp) |
| `base_manager_utest` | Only [managerLogSink_test.cpp](test/src/unit/managerLogSink_test.cpp): the sink (`ManagerLogSinkTest.*`, `ManagerLogSinkDeathTest.*`) and the manager home (`ManagerHome.*`, `ManagerHomeAbsolute.*`). The sink and the manager mode are global process state, hence the separate binary. The fixtures work in their own `mkdtemp` directory (the child of a death test inherits it); `ManagerHomeAbsolute` touches no disk. |
| `base_logger_utest` | [logger_test.cpp](test/src/unit/logger_test.cpp) |

```bash
$ENGINE_BUILD/source/base/base_utest --gtest_filter='DropToUser.*'
ctest --test-dir $ENGINE_BUILD -R 'DropTo|ManagerLogSink' -V
```

Where each contract is exercised:

| Contract | Tests |
|---|---|
| Daemonization | `GoDaemonFunctionalTest.*` (real forks in a child), `GoDaemonErrors.*` (every failing call, with fakes) |
| PID file | `CreatePIDTest.*`, `CreatePIDErrors.*` |
| User/group lookup and privilege drop | `LookupUid.*`, `LookupGid.*`, `DropToUser.*`, `DropToGroup.*`, `DropErrors.*` |
| Manager home | `ManagerHome.*` (incl. the exits `ManagerHomeEnvNotDirectoryExits`, `ExeNotDirectoryExits`), `ManagerHomeAbsolute.*` |
| Log sink | `ManagerLogSinkTest.*`, `ManagerLogSinkDeathTest.*` |

`ctest` discovers the cases with `gtest_discover_tests`; names are `<Suite>.<Test>`, without a binary prefix.

**Tests that need root** (they skip otherwise): `DropToUser.DropsPrivilegesInChild`, `DropToUser.MessagesAfterDropInChild`, `DropToGroup.DropsToTargetGroupInChild` and `ManagerLogSinkTest.CreateAsRootReal`. The last one also needs the `wazuh-manager` group, and the group of a new log file is set only when running as root. `DropToUser.ThrowsWhenNotPermitted` runs both with and without root.

To run the unprivileged pass:

```bash
cd /tmp && setpriv --reuid 65534 --regid 65534 --clear-groups env TMPDIR=/tmp <binary>
```
