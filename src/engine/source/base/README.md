# Base Module

## Overview

The **base** module is a static library (`base`, see [CMakeLists.txt](CMakeLists.txt)) with the common utilities of the Wazuh Engine: JSON, graphs, expressions, logging, process helpers, the manager configuration loader and small string/IP/time utilities. Every other engine module links against it.

This README covers in depth three pieces: the **manager log sink** (the writer behind `logs/wazuh-manager.log` and `logs/wazuh-manager.json` in manager mode), the **process helpers** (daemonization, PID file, user/group lookup and privilege drop, manager home) and the **JSON path writer** (a scoped writer for building wide JSON objects member by member). The rest is listed in the directory structure below; read the headers for their API.

## Directory Structure

```
base/
├── CMakeLists.txt
├── README.md
├── include/base/
│   ├── json.hpp                # base::json::Json, the JSON document type used across the engine (an allocation failure throws std::bad_alloc)
│   ├── jsonPathWriter.hpp      # json::PathWriter, indexed member lookup for wide objects (see "JSON Path Writer")
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
│   └── utils/                  # stringUtils, ipUtils, timeUtils, generator, communityId, singletonLocator, ...
├── src/                        # Implementations (managerLogSink.cpp, process.cpp, logging.cpp, ...)
│   └── jsonNameCompare.hpp     # Internal header: member-name comparison shared by the path writer, the merge and the bulk erase (not installed)
├── test/include/               # base::test INTERFACE include directory (test helpers, incl. logCapture.hpp)
├── test/src/unit/              # GoogleTest unit tests
└── benchmark/                  # base_benchmark (eventParser, json)
```

## Object member inspection

`Json::anyMemberName(predicate, path)` checks decoded, length-aware names of the selected object's
immediate members without copying values or descending into them. It preserves repeated names and
stops at the first match. Missing paths and non-objects return false. Predicate views borrow the
immutable document; predicate exceptions propagate. Ingestion uses this to reject dotted aliases
of its identity path while leaving generic JSON Pointer and merge semantics unchanged.

## Manager Log Sink

Header: [include/base/managerLogSink.hpp](include/base/managerLogSink.hpp). Implementation: [src/managerLogSink.cpp](src/managerLogSink.cpp).

In manager mode the engine writes `logs/wazuh-manager.log` and `logs/wazuh-manager.json`, relative to the current directory (the manager home after `main()`'s `chdir`). The lines are the same plain and JSON lines the C logger produces, and the destinations are written in the order JSON, plain, stderr.

Behaviour:

- **One `write()` per destination.** Each line is composed in memory and written with a single `write()` per destination, under one process-wide mutex. A short write drops the rest of that line; it is not retried.
- **Files opened per line with `O_APPEND`.** A rotation (rename) of the file is picked up by the next line.
- **Only a lone regular file is written.** `logs/` is writable by the `wazuh-manager` account and the engine logs as root until it drops privileges, so the name is opened with `O_NOFOLLOW | O_NONBLOCK` and the descriptor must be a regular file with one link, the rule the C logger applies through `w_openat_nofollow_vetted()`. A symlink, hard link, FIFO or device at the name drops the line for that destination.
- **New files.** Created with mode 0660. The group is set to `wazuh-manager` (via `base::process::lookupGid`) only when running as root; if the lookup fails, the file keeps the group of its creator. A failing `fchmod` or `fchown` does not prevent the line from being written.
- **Never throws, preserves `errno`.** The caller's `errno` is restored after every call.
- **No-op before `initManager()`.** Unit tests and `main()` before the call write nothing and touch no file.
- **Immortal state.** The options, dependencies and mutex are allocated once and never destroyed, so late lines (exit handlers, late threads) never touch a destroyed mutex.
- **Fork safety.** The mutex crosses the `fork()` calls of `goDaemon()` only because, in manager mode, no other thread exists yet: `main.cpp` calls `initManager()` before `goDaemon()`.
- **Injection.** `ManagerLogDeps` holds the system calls (`open`, `fstat`, `write`, `fchown`, ...) and clock/pid/root/group lookups; an empty member means the real call.

## Process Helpers

Header: [include/base/process.hpp](include/base/process.hpp). Implementation: [src/process.cpp](src/process.cpp).

| Function | Behaviour |
|---|---|
| `goDaemon` | fork, `setsid`, fork, `umask(027)`, stdin/stdout/stderr redirected to `/dev/null`. Returns a `StartupReport` to the grandchild. The **original process does not leave at the first fork**: it closes the write end of a startup channel, blocks reading the verdict, and `_exit`s with it — 0 only if the grandchild reported ready, `EXIT_FAILURE` otherwise, writing the reported cause to its still-connected stderr. The intermediate child leaves with `EXIT_SUCCESS`. Both parents still use a real `_exit` (no exit handlers). Throws after the first fork send the cause through the channel before propagating. |
| `StartupReport` | The grandchild's handle on that channel. **Single shot**: `reportReady()` / `reportFailure(text)` write, close the descriptor and leave the object disconnected for good; every later call is a no-op, which is what keeps a failure raised hours later (the `try` in `main.cpp` also covers the service loop) from writing into a reused descriptor. **Move-only**, so the descriptor is never double-closed. Default-constructed it is already disconnected, and that is what foreground mode (`-f`) uses: every method a no-op, no mode branch in `main.cpp`. |
| `createPID` | Writes `<path>/<name>-<pid>.pid` with mode exactly 0640 (`fchmod`) and content `<pid>\n`; retries on `EINTR` and completes partial writes. |
| `lookupUid` / `lookupGid` | Reentrant lookups. The buffer starts at the `sysconf` hint (1024 when undefined, capped at 64 KiB) and doubles up to 64 KiB. |
| `dropToGroup` | `setgroups` + `setgid`. Call it before `dropToUser`. |
| `dropToUser` | `setuid` + `seteuid`. Irreversible when leaving root. |
| `resolveManagerHome` | Order: `WAZUH_MANAGER_FORCE_HOME` as is, then a non-empty `WAZUH_MANAGER_HOME`, then the dirname of `/proc/self/exe` cut at the first `"/bin"`. When the result of the 2nd or 3rd is not a directory it writes a CRITICAL 1108 line to stderr and exits with status 1. |
| `setManagerMode` / `getWazuhHome` | Manager mode is process-wide and irreversible. Outside it, `getWazuhHome()` returns the current working directory. |

Injection: `ProcessSysCalls` groups 18 system calls (`fork`, `setsid`, `umask`, `open`, `dup2`, `close`, `fchmod`, `write`, `setgroups`, `setgid`, `setuid`, `seteuid`, `sysconf`, `pipe2`, `read`, `pthread_sigmask`, `sigtimedwait`, `fcntl`); an empty member is the real call. Outside the seam is `_exit` (checked by `GoDaemonFunctionalTest.ParentsSkipExitHandlers`); `umask` is injectable, but a test that leaves it empty gets the real `umask(027)` applied to itself. `UserLookup` and `GroupLookup` are injectable as well.

**Startup channel.** The pipe is created with `pipe2(O_CLOEXEC)` before the first fork, and both ends are lifted above
`STDERR_FILENO` with `F_DUPFD_CLOEXEC` when they land on 0/1/2: otherwise the `dup2` of `/dev/null` would silently
replace the write end and a healthy start would be reported as a failure. Exactly one process owns the write end (the
grandchild), so end of file is a reliable "died without a verdict", and the reader treats it as a failure — which is
what covers `exit()`, `std::terminate` and `SIGKILL` without touching them. Every write to the channel, including the
ones `goDaemon` makes before the object exists, goes through a helper that blocks `SIGPIPE` with `pthread_sigmask` and
drains it with `sigtimedwait`: `write(2)` on a pipe whose reader is gone does **not** return `EPIPE` while `SIGPIPE`
keeps its default disposition — it kills the process — and the engine only sets `SIG_IGN` much later. Reads and writes
retry on `EINTR` and complete short writes; any other `errno` gives up rather than spinning.

## JSON Path Writer

Header: [include/base/jsonPathWriter.hpp](include/base/jsonPathWriter.hpp). Implementation: [src/jsonPathWriter.cpp](src/jsonPathWriter.cpp). Namespace `json`.

A `Json` setter looks a member up by scanning the members of the object on every call, so building an object of N members one call at a time costs O(N^2) name comparisons. `json::PathWriter` is a scoped writer over a `json::Json` that keeps an ordered index (name to position) for each object with more than `indexThreshold` members (`DEFAULT_INDEX_THRESHOLD` = 128), which makes the same N writes or lookups O(N log N) whatever the member names are.

Use it in code that writes or looks up many members of the same object in one go (for example, turning one input into one document). For a handful of fixed fields use `Json` directly.

**Guarantee.** Every operation gives exactly the result of the `Json` method of the same name: same document, same return value and same exception.

| Kind | Operations (same name and arguments as in `Json`) |
|---|---|
| Writes | `set`, `setString`, `setStringAsMembers`, `setNullAsMembers`, `setObject`, `setArray`, `appendString`, `appendJson` |
| Reads | `exists`, `isObject`, `isArray`, `size`, `getJson` |
| Relative to an anchor | `root`, `find`, `ensure`, the anchor overloads of `setString`, `setObject`, `appendString`, `appendJson`, `exists`, `isObject`, `isArray` and `size`, and `wrapInArray` (see "Anchors") |
| Diagnostics | `indexedObjects()`: number of index entries currently held (diagnostics and tests) |

**Rules of use** (from the header):

1. While the writer is alive, the document is modified only through it, and no member is erased or reordered. Reading the document directly stays valid, but only reads made through the writer use the index.
2. The `Json` outlives the writer and is neither moved nor assigned while the writer is alive.
3. A writer is not shared between threads.
4. The result of an operation is the result of the `Json` method of the same name; if in doubt, `Json` is the reference.
5. A value written through the writer is never the target document itself.
6. An anchor is used only with the writer that created it, and only while it is valid. The writer rejects an anchor created by another live writer; it does not check whether an anchor is still valid (see **Anchors** below).

**Allocation failures.** A write (`set*`, `append*`, `ensure`, `wrapInArray`, by absolute path or by anchor) that throws `std::bad_alloc` leaves the document exactly as it was, and the writer stays usable. The index is exact or absent: an entry that can be matched always describes the current members, and when the index cannot allocate after a member was attached, the write still succeeds, the entry is dropped and the next lookup rebuilds it. Anchors that were valid before a failed write stay valid.

Objects at or below the threshold are scanned exactly like `Json` does, and constructing a writer allocates nothing: the index of an object is built the first time that object is looked up above the threshold (reads included). That first lookup costs more than the single scan `Json` would do, so keep one writer for the whole construction of a document instead of creating one per operation; index entries live until the writer is destroyed. The writer is neither copyable nor movable.

```cpp
json::Json doc;
{
    json::PathWriter writer(doc);               // allocates nothing
    for (const auto& [name, value] : fields)
    {
        writer.setString(value, "/" + name);    // name already escaped as a JSON pointer token; O(log N) on wide objects
    }
    const bool hasUser = writer.exists("/user"); // read through the writer, not through doc
}                                                // scope end: doc is free to use directly again
```

**Anchors.** An operation that takes an absolute path resolves it from the root of the document on every call, so its cost grows with the length of the path. Code that walks a tree and writes under the node it is visiting can resolve that node once, keep it as a `PathWriter::Anchor` (opaque, copyable and small; created only by `root()`, `find()` and `ensure()`), and pass paths relative to it: the overloads that take an anchor run the same code as the absolute ones, starting at the anchored node instead of at the root.

- **Guarantee.** For an anchor that names the node of absolute path A and a valid relative path R, `op(anchor, R)` leaves the same document, returns the same value and throws the same exception type as `op(A + R)`, with A written as a plain JSON pointer (`/a/b`), not in the URI fragment form (`#/a/b`), where a `%` in R would be read as an escape.
- **Relative path.** It is valid when it is empty (the anchored node itself) or starts with `/` and is a valid JSON pointer. The URI fragment form (`#/a`) is not valid. Every overload that takes an anchor, the reads included, throws `std::runtime_error` on an invalid relative path.
- **`find` and `ensure`.** `find(from, relPath)` resolves without creating anything and returns `std::nullopt` if the path does not exist. `ensure(from, relPath)` creates the node and whatever is missing on the way, exactly what a write to that path would create; an existing target is not touched, and a new node is null until something is written into it.
- **`wrapInArray(from, relPath)`.** Replaces the value by an array whose only element is that value. The value is moved, not copied, so it takes constant time and an indexed object keeps its index entry. It returns `false`, leaving the document untouched, if the path does not exist.
- **Owner.** An anchor is used only with the writer that created it, and only while that writer is alive. Every overload that takes an anchor throws `std::runtime_error`, before reading or changing anything, if the anchor was created by another live writer. A writer is told apart by its address, so an anchor that outlives its writer is not detected (rule 4 below).

Validity of an anchor over time is the caller's responsibility; **the writer does not check it**:

1. An anchor is valid while the immediate container of its node does not reallocate. It stops being valid when a member is added to the parent object, an element is appended to the parent array, the parent changes type (a write through it turns an array into an object, or the reverse, and destroys its elements), or an ancestor is overwritten. Writing inside the anchored node (adding members to it, turning it into an object or an array in place) does not invalidate it.
2. The anchor of the root is valid for as long as the writer lives.
3. After `wrapInArray`, an anchor to the wrapped node is still valid and names the same path, which now holds the array; anchors to its former descendants point to live memory but name the path below element 0.
4. No anchor is valid after the writer that created it is destroyed.

Using an anchor after it stopped being valid is not supported and has no guaranteed outcome: the write may be lost or may land in the live document.

```cpp
json::Json doc;
json::PathWriter writer(doc);
const auto root = writer.root();
const auto host = writer.ensure(root, "/host");              // resolved once, created if missing
writer.setString(host, "web-01", "/name");                   // relative to /host
writer.setObject(host, "/os");                               // writing inside the anchor keeps it valid
if (const auto os = writer.find(host, "/os"))                // child anchor, nullopt if absent
{
    writer.setString(*os, "linux", "/type");
}
```

## JSON Merge and Bulk Erase

Header: [include/base/json.hpp](include/base/json.hpp). Implementation: [src/json.cpp](src/json.cpp). Namespace `json`.

**`Json::merge` between objects.** Each member of the source is resolved in the destination with one lookup, which scans the destination. Once the scans of one merge have visited more than `Json::MERGE_INDEX_SCAN_FACTOR` times the number of members of the destination, the rest of its lookups go through a local ordered index of the destination members: building the index costs a small fraction of the scanning already done, so a merge is not noticeably slower than plain scanning and the cost of merging wide objects grows almost linearly with the number of members. A recursive merge descends into the member it found. Merging arrays is a different path: each source element is compared with every destination element.

**Allocation failures in `Json::merge`.** The guarantee is "usable", not strong: when an allocation fails midway, `std::bad_alloc` propagates and the destination keeps the part of the source that was already merged. Every member or element is either what it was before or its complete final value (a name that the source repeats may hold the complete value of an earlier occurrence, and in a recursive merge this holds node by node), never a half-written member and never a new duplicate name: the value and the name are copied before they are added, and a replacement is copied before it is assigned. Repeating the same merge is not guaranteed to complete the result. It does not, for example, when a recursive merge meets a name that the source repeats with values of different kinds (the destination can be left holding the later occurrence, and the repeated merge then fails on the earlier one with the error a merge of mismatched kinds always gives); when an array element is an object with a repeated name (it never compares equal to its own copy, so the repeated merge appends it again); or when the source of a same-document merge (`merge(isRecursive, sourcePath, path)`) lies inside a destination member that the merge itself replaces (the replacement detaches the source, the members not yet merged are lost and the repeated merge fails with the path-not-found error). A same-document merge erases its source only when the merge finished. In every case the document stays usable.

**Destination path in URI-fragment form.** A destination path written as `#/...` is resolved once, at the start of the call. Member names met while descending are never read again as part of a fragment.

**`Json::eraseMembersEqualTo(path, value)`.** Erases, in a single pass, the members of the object at `path` whose value equals `value`; the members that stay keep their order. With a repeated member name, the leading run of equal occurrences of that name is erased and the first occurrence that differs keeps the later ones. Names are compared with their whole length. It returns the number of members erased, and 0 with the document untouched when the path does not exist or is not an object. The builder helper `delete_fields_with_value` uses it.

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

## Generators

Header: [include/base/utils/generator.hpp](include/base/utils/generator.hpp). Implementation: [src/utils/generator.cpp](src/utils/generator.cpp). Namespace `base::utils::generators`.

`generateDocId` and `generateUUIDv4` draw their random bytes from OpenSSL `RAND_bytes` (through `fillRandom`); a failure is an exception, never a fallback to a weaker source. `randomHexString` is unchanged and still uses `mt19937`.

| Function | Behaviour |
|---|---|
| `fillRandom(out, n)` | Fills `n` bytes with `RAND_bytes`. Throws `std::runtime_error` when `n > INT_MAX` (the source is not called) or when the source fails (message with the OpenSSL error). |
| `generateDocId` | Document id for an indexer write: 8 bytes big-endian of a per-thread strictly increasing nanosecond clock (`max(systemEpochNanos(), last + 1)`) followed by a 12-byte random prefix drawn once per thread, encoded as unpadded base64url: always `DOC_ID_LENGTH` (27) characters of `[A-Za-z0-9_-]`. Lock-free after the first id of each thread (the first one goes through a `std::call_once` that registers the fork handler): the state is a trivial `thread_local`. Two ids can only collide if two threads draw the same 96-bit prefix and stamp the same nanosecond, or once a thread's clock reaches `INT64_MAX` (year 2262): there it saturates instead of overflowing and the thread repeats its last id. Throws if the prefix cannot be drawn; the next call on that thread retries. |
| `generateUUIDv4` | Random UUID version 4 (`wazuh.event.id`, content resource ids): 36 lowercase characters in the 8-4-4-4-12 layout, version `4` at index 14 and variant `[89ab]` at index 19 (122 random bits). Each id takes 16 bytes from a per-thread 4096-byte buffer filled by `fillRandom` when it runs out, so one draw serves 256 ids; the buffer is a trivial `thread_local` (4 KiB of static TLS in every thread of the process). No shared lock or atomic of its own per id. Throws if a refill fails, without using any byte of the failed draw; the next call on that thread retries. |
| `isValidResourceId`, `randomHexString` | Unchanged (resource id rules; hex string for temporary names). |

`fork()`: a child-side `pthread_atfork` handler, registered once by the first `generateDocId` or `generateUUIDv4` call, marks the per-thread state of the forking thread as uninitialized (the doc id prefix and the UUID buffer). The child obtains fresh random bytes before generating its next id, preventing replay of the inherited state. The handler only stores (no OpenSSL, no allocation).

Test seam: `detail::exchangeRandBytesForTesting(fn)` replaces the source read by `fillRandom` (`nullptr` restores `RAND_bytes`) and returns the previous one; `detail::DocIdGenerator` runs the same encoding core over an injected prefix and clock. Tests: `GeneratorTest.*` in [generator_test.cpp](test/src/unit/utils/generator_test.cpp) (run in `base_utest`), including the vectors shared with the id spike and, for `generateUUIDv4`, the exact ids built from known source bytes, one draw per 256 ids, failure and retry, and new ids after `fork()` (`GeneratorTest.UUIDv4*`).

## Testing

Four binaries are built with `ENGINE_TEST=y` (see [CMakeLists.txt](CMakeLists.txt)):

| Binary | Content |
|---|---|
| `base_utest` | The files listed in [CMakeLists.txt](CMakeLists.txt): `test/src/unit/*_test.cpp` and `test/src/unit/utils/*_test.cpp` except the three below, including [process_test.cpp](test/src/unit/process_test.cpp) |
| `base_manager_utest` | Only [managerLogSink_test.cpp](test/src/unit/managerLogSink_test.cpp): the sink (`ManagerLogSinkTest.*`, `ManagerLogSinkDeathTest.*`) and the manager home (`ManagerHome.*`, `ManagerHomeAbsolute.*`). The sink and the manager mode are global process state, hence the separate binary. The fixtures work in their own `mkdtemp` directory (the child of a death test inherits it); `ManagerHomeAbsolute` touches no disk. |
| `base_logger_utest` | [logger_test.cpp](test/src/unit/logger_test.cpp) |
| `base_json_log_utest` | [jsonSanitizeLog_test.cpp](test/src/unit/jsonSanitizeLog_test.cpp): `Json::str()` warns about the first document it had to sanitize and logs the rest at debug, a decision taken once per process, so telling the first occurrence from the rest needs a binary of its own. [logCapture_test.cpp](test/src/unit/logCapture_test.cpp) rides along in the same binary: `LogCapture.*` covers the helper itself (the level it holds and restores, what it selects, `clear()`, nesting and the sink it takes off), which no test asserting on logs would notice breaking. |

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
| JSON allocation failure | `JsonAllocationInjectionTest.*` (`json::BaseAllocator::failAt` fails the n-th allocation; every mutation is swept through its allocation points and the document must stay usable; the `Merge*` cases pin the "usable" guarantee of `Json::merge`: a failure leaves each node as it was or complete (for a name that the source repeats, complete with the value of one of its occurrences), no duplicate name; the same-document merge keeps its source until it finishes, unless the merge itself replaces the member that holds it; and three cases pin shapes in which repeating the merge does not complete it), `JsonAllocationFailureTest.*` (`RLIMIT_AS` death tests, skipped under the sanitizers) |
| `Json::str()` sanitization log | `JsonSanitizeLog.WarnsOnceThenDebugsAndNeverLogsTheEvent` (warning once, debug afterwards, and no part of the event in either line) |
| JSON path writer | Differential tests against `Json` in [jsonPathWriter_test.cpp](test/src/unit/jsonPathWriter_test.cpp) (`base_utest`); `PathWriterInjectionTest.*` in [jsonPathWriter_injection_test.cpp](test/src/unit/jsonPathWriter_injection_test.cpp) (`base_utest`) fails every allocation of each write and checks the document, the index and the anchors afterwards; benchmarks `BM_PathWriter*` in [jsonSet_bench.cpp](benchmark/src/jsonSet_bench.cpp) (`base_benchmark`) |

`ctest` discovers the cases with `gtest_discover_tests`; names are `<Suite>.<Test>`, without a binary prefix.

**Tests that need root** (they skip otherwise): `DropToUser.DropsPrivilegesInChild`, `DropToUser.MessagesAfterDropInChild`, `DropToGroup.DropsToTargetGroupInChild` and `ManagerLogSinkTest.CreateAsRootReal`. The last one also needs the `wazuh-manager` group, and the group of a new log file is set only when running as root. `DropToUser.ThrowsWhenNotPermitted` runs both with and without root.

To run the unprivileged pass:

```bash
cd /tmp && setpriv --reuid 65534 --regid 65534 --clear-groups env TMPDIR=/tmp <binary>
```

### Asserting on log output

[test/include/base/logCapture.hpp](test/include/base/logCapture.hpp) gives any test linking `base::test` a `base::test::LogCapture`: it adds a sink to the logger `logging::testInit()` starts, holds the level it is built with while it lives, and hands back the records (level plus message, no header) with `records()` or `records(level)`. It takes the sink off again and restores the level on destruction, so production logging is untouched and a test that builds no capture logs as before. Only standalone mode reaches that logger, so a test that forces manager mode has to read the manager sink instead; the constructor throws there rather than hand back a capture that would stay silently empty.

```cpp
base::test::LogCapture capture {logging::Level::Debug};
somethingThatLogs();
ASSERT_EQ(capture.records(logging::Level::Warn).size(), 1);
```

The helper's own contract is checked by `LogCapture.*` in `base_json_log_utest`.
