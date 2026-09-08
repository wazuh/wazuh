# 05 — Clean design and reuse findings

Two themes: (A) the module reimplements a lot of code that already exists in-tree, and (B) its own
internal structure is dominated by mechanical boilerplate that a small amount of type design removes.

---

## Part A — Reimplementation of existing in-tree code

### D1 — A parallel hashing implementation

`hash_helper.cpp` (89 lines) reimplements a triple-digest single-pass file hash with a size cap.
FIM already ships exactly that:

```c
int OS_MD5_SHA1_SHA256_File(const char *fname, os_md5 md5output, os_sha1 sha1output,
                            os_sha256 sha256output, int mode, size_t max_size);
```
`src/shared/os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h:19-24`

The host FIM call site (`src/syscheckd/src/file/file.c:858-883`) also shows the **semantics the
container path got wrong**:

```c
// We won't calculate hash for symbolic links, empty or large files
if (S_ISREG(statbuf->st_mode) && (statbuf->st_size > 0 &&
    (size_t)statbuf->st_size < syscheck.file_max_size) &&
    (configuration->options & (CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM))) {
    if (OS_MD5_SHA1_SHA256_File(...) < 0) { ... }
}
if ((configuration->options & CHECK_MD5SUM) == 0)  { data->hash_md5[0]  = '\0'; }
if ((configuration->options & CHECK_SHA1SUM) == 0) { data->hash_sha1[0] = '\0'; }
if ((configuration->options & CHECK_SHA256SUM) == 0) { data->hash_sha256[0] = '\0'; }
```

Host FIM **skips** files larger than `file_max_size` and blanks the digests. The container module
**truncates and emits a prefix digest** instead ([C2](03-findings-correctness.md#c2--truncated-hashes-are-emitted-as-if-they-were-whole-file-hashes)) — the defect is a direct consequence of not
reusing the host function. Host FIM also pre-seeds the well-known empty-file digests for
zero-length files and symlinks; the container rows leave them empty, so the two paths disagree on
identical inputs.

**Recommendation:** call `OS_MD5_SHA1_SHA256_File` and honour `CHECK_MD5SUM`/`CHECK_SHA1SUM`/
`CHECK_SHA256SUM`. Deletes `hash_helper.cpp` and fixes C2 and [P7](04-findings-performance.md#p7--hashing-cost-is-3-larger-than-any-configuration-requires) at once.

### D2 — A parallel file walk, missing the throttle that already exists

`rootfs_file_walker.cpp` (140 lines) reimplements readdir recursion, depth limiting, and the
symlink/special-file policy. Host FIM has `fim_checker` / `fim_directory` / `fim_file`
(`file.c:893`, `:999`, `:1066`) doing the same, plus two things the container walker lacks:

- **A per-file rate limiter.** `fim_file()` calls `check_max_fps()` as its *first* action
  (`file.c:1077`), a process-global token bucket driven by `syscheck.max_files_per_second`
  (`run_check.c:462-505`). It is declared publicly in `syscheck.h:201`. Because it is process-global,
  a container walker that called it would correctly share one budget with the host walk.
  **This is the throttle NFR3 demands, already implemented, and the container path never calls it.**
- **Filesystem-type skipping** — `HasFilesystem(path, syscheck.skip_fs)` (`file.c:962`), which is
  most of the answer to [C8](03-findings-correctness.md#c8--the-file-walk-has-no-mount-boundary-guard-and-can-escape-into-the-host-filesystem)'s mount-escape problem.

What is *genuinely* new in `rootfs_file_walker.cpp` is only: rooting the walk at `/proc/<pid>/root`,
reporting logical in-container paths, and the `max_files`/`truncated` cap (which host FIM does not
have and arguably should).

**Recommendation:** rather than a second walker, parameterise the host walk with a path prefix and a
logical-path mapping. If the C/C++ boundary makes that impractical in this slice, at minimum call
`check_max_fps()` from the container walk and adopt `skip_fs`.

### D3 — A parallel `/proc/net` parser and interface collector

| Reimplemented | Already exists |
| --- | --- |
| `network_scanner.cpp` hex address decode + `/proc/net/{tcp,udp,tcp6,udp6}` row parsing (201 lines) | `PortImpl` + `LinuxPortWrapper(portType, row)` — a pure *row string → JSON* transform (`src/data_provider/src/ports/portLinuxWrapper.h`; call shape at `sysInfoLinux.cpp:570`) |
| `network_scanner.cpp` `BuildInodeOwnerMap` (fd → socket inode → pid/comm) | `portProcessInfo(const std::string& procPath, const std::deque<int64_t>& inodes)` — **already takes the proc dir as a parameter** (`sysInfoLinux.cpp:404`); it is file-local, so publishing it is a one-line header change |
| `interface_scanner.cpp` `ifaddrs*` → interface/address JSON (165 lines) | `NetworkLinuxInterface(ifaddrs*)` + `FactoryLinuxNetwork::create` + `LinuxNetworkImpl::buildNetworkData` (`networkLinuxWrapper.h:192,256`; `networkInterfaceLinux.h:22,26,36`) |

The interface case is the starkest: `ScanContainerInterfaces` already produces an `ifaddrs*` on the
`setns`'d thread — precisely the input `NetworkLinuxInterface` consumes — and then hand-rolls the
field extraction anyway. The `setns` hop is the genuinely new part and is not replaceable; the JSON
building is pure duplication.

**Recommendation:** keep the `setns` hop, hand the resulting `ifaddrs*` to
`FactoryLinuxNetwork`/`LinuxNetworkImpl`. Same for ports: keep the container-scoped inode filter,
delegate row parsing to `LinuxPortWrapper`. Both also eliminate the schema-drift risk in D6.

### D4 — Package scanning: the right instinct, blocked by a build-graph problem

`package_scanner.cpp` deliberately reuses sysinfo's header-only `parseDpkg`/`parseRpm`/
`BerkeleyRpmDBReader` — good. But it reimplements the *driver* loop, and its own comment explains
why:

```cpp
// Same block-splitting shape as sysinfo's getDpkgInfo() — that function is
// directly reusable (it takes the status-file path), but compiling its TU
// drags FileSystemWrapper + the python-package walker into this module, so
// the 20-line loop lives here and the actual parser is the reused one.
```
`package_scanner.cpp:194-197`

The observation is accurate — `getDpkgInfo(const std::string& libPath, std::function<void(nlohmann::json&)> callback)`
(`packageLinuxDataRetriever.h:39`) is already path-parameterised and directly callable with
`/proc/<pid>/root/var/lib/dpkg/status`. This is a **build-graph problem, not a design problem**, and
it should be fixed by splitting the TU rather than worked around by duplicating the driver.

### D5 — Users: an injectable seam already exists and was not used

`UsersProvider` reads the passwd file through an **injectable** wrapper, not a raw `fopen`:

```cpp
FILE* passwd_file = m_sysWrapper->fopen("/etc/passwd", "r");
```
`src/data_provider/src/extended_sources/users/src/users_linux.cpp:76`

with `virtual FILE* fopen(const char*, const char*) = 0;` (`isystem_wrapper.hpp:30`) and
`IPasswdWrapperLinux::fgetpwent_r(FILE* stream, …)` (`ipasswd_wrapper.hpp:28`) being **stream-based**.
An `ISystemWrapper` whose `fopen` prefixes `/proc/<pid>/root` makes `UsersProvider::collect()` work
against a container **with no change to the provider at all**.

`GroupsProvider` is not as fortunate — `IGroupWrapperLinux` is `setgrent`/`getgrent_r`-based with no
file-stream variant, so the hand-written group parser is justified.

### D6 — Two hand-maintained schema mirrors that will drift

1. `baseline_rows.cpp` (652 lines) hand-writes the dbsync column set for 11 tables, mirroring
   `syscollectorTablesDef.hpp`. Nothing links them; a column rename breaks silently at runtime.
2. `container_baseline_fim_bridge.c:73-155` hand-maintains the flat-dbsync → ECS transform with
   `copy_if_present` × 10 and `cJSON_DeleteItemFromObject` × 20, mirroring what
   `Syscollector::ecsData()` and `FileItem::createJSON()` do for host rows.

The module's own headers admit the second one is unresolved:

```
/// NOTE: this is a draft ECS-ish shape (process.*, container.*), not a byte-for-
/// byte reproduction of Syscollector::ecsData()'s mapping … Wire this through
/// the real ecsData() transform once that schema is finalized.
```
`baseline_rows.hpp:59-64`

**Recommendation:** emit rows through the *same* transform host rows use. Since the container path
already reaches `Syscollector::processEvent` → `ecsData()` via the dbsync tables, the correct move is
to delete the `Build*Json` family entirely (it is already dead — see D8) and let one transform serve
both sources.

### D7 — There is no way to point sysinfo at a rootfs, and that is the real architectural gap

For completeness, because it is the honest counterweight to D3–D5: `ISysInfo`
(`sysInfoInterface.h:17-38`) has no rootfs/prefix parameter, and `IFileSystemWrapper` is **not**
threaded through the collectors that matter — `getHardware`, `getOsInfo`, `getPorts`, `getNetworks`,
`getProcessesInfo`, and the dpkg/rpm/snap package driver all construct the concrete wrapper on the
stack:

```cpp
static void getPackages(const std::function<void(nlohmann::json&)>& callback)
{
    const file_system::FileSystemWrapper fs;      // concrete, not injected
    if (fs.is_directory(DPKG_PATH))  { getDpkgInfo(DPKG_STATUS_PATH, callback); }
    ...
}
```
`src/data_provider/src/packages/packageLinuxDataRetriever.h:57-75`

with paths as compile-time constants in `sharedDefs.h:18-34`.

So per-container collection genuinely cannot be obtained by configuration alone today. But
`ISysInfo` **is** already an injection point in three modules (`syscollector.hpp:53`,
`agent_info_impl.hpp:54`, `sca_policy_check.hpp:141`), which makes
`class ContainerSysInfo : public ISysInfo` the in-idiom extension path — and the cleanest long-term
answer. See [06](06-proposed-architecture.md#65-the-collector-seam).

### D8 — Dead and mislabelled code

| Item | Evidence |
| --- | --- |
| `cbaseline_run_fim`, `cbaseline_run_syscollector`, and all 12 `Build*Json` functions | Zero call sites in-tree. ~170 lines of exported, documented, maintained, uncalled code — and it is not merely unused but **broken** (see [C12](03-findings-correctness.md#c12--processstart-is-silently-dropped-in-the-sync-protocol-path)). |
| `IsOverlayWhiteout` | Cannot fire under `/proc/<pid>/root` addressing ([C13](03-findings-correctness.md#c13--dead-overlay-whiteout-handling-signals-an-unresolved-mechanism-choice)), yet has a dedicated unit test. |
| `OsBaselineRow::family` | Parsed from `ID_LIKE` (`os_scanner.cpp:82`), dropped by the serialiser (`baseline_rows.cpp:318`). |
| `container_baseline.h:53-54` documents `<directories type="kubernetes">` / `k8s_monitored_path_t` | That config surface no longer exists — removed by `66301af90d`. The header is actively misleading. |
| The module is named `container_baseline` but is **not a wmodule** | No `wm_container_baseline.c`, no `wmodules.h` entry, no ossec.conf block. It is a shared library. Contrast `container_instances`, which does have `wmodules-container-instances.c`. |
| The FIM driver lives in `src/syscheckd/src/ebpf/` and ships in `libfimebpf.so` | It has nothing to do with eBPF; `grep -n 'container' ebpf_whodata.cpp` → zero hits. Placement is a build convenience that misleads about module boundaries. |

---

## Part B — Internal structure

### D9 — 36 near-identical functions where 3 would do

`baseline_rows.cpp` is 652 lines, and the great majority is mechanical:

- **12 identical `ApplyIdentity` overloads.** Every one is byte-for-byte the same two assignments:

```cpp
void ApplyIdentity(FileBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container    = id.context;
}
// … ×12, differing only in the parameter type
```

- **12 `Build*Json` functions** (dead — D8) and **12 `Build*DbsyncRow` functions**, each a flat
  sequence of `data["col"] = row.field;`.

The root cause is that the 12 row structs each *repeat* the same two container fields rather than
sharing them:

```cpp
struct FileBaselineRow {
    /* … class-specific fields … */
    std::string        container_id;
    ContainerContextPtr container;   // repeated verbatim in all 12 structs
};
```

**Recommendation:** a single `ContainerScoped` base (or member) struct carrying
`container_id` + `container`, and `ApplyIdentity` becomes one function:

```cpp
struct ContainerScoped {
    std::string         container_id;
    ContainerContextPtr container;
};

inline void ApplyIdentity(ContainerScoped& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container    = id.context;
}
```

12 functions → 1. For the serialisers, a per-type field-descriptor table (name, member pointer)
consumed by one generic writer collapses 24 hand-written functions into 12 short declarative tables
plus one loop — and, critically, makes the column set *inspectable*, which is what would let it be
checked against `syscollectorTablesDef.hpp` at build or test time instead of drifting silently (D6).

### D10 — Process-global mutable state in a library

```cpp
std::atomic<bool> g_everSawContainers{false};
```
`container_baseline_scanner.cpp:40`

Correctly typed, and its purpose (amortise the cold-start retry so a recurring caller does not pay
5 s every scan) is sound. But it is **file-scope mutable state in a shared library loaded into two
different daemons**, so its value depends on which consumer ran first within a process, and it cannot
be reset by a test. There is no unit test for the orchestrator, so this is untested behaviour.

**Recommendation:** move it into a `BaselineSession`/`BaselineRunner` object that owns the client, the
retry state, the per-run caches (P6's image-digest cache), and the PID index. That object is also the
natural home for the streaming and concurrency changes — see [06](06-proposed-architecture.md).

### D11 — Blocking sleeps inside a library call

```cpp
constexpr int  kListRetryAttempts = 10;
constexpr auto kListRetryDelay    = std::chrono::milliseconds{500};
```
`container_baseline_scanner.cpp:38-39`

Up to 5 s of `std::this_thread::sleep_for` inside a synchronous C API call, on the caller's thread —
which for FIM is syscheckd's `main()`. The consumer side adds another 5 s of socket polling
(`container_baseline_fim_bridge.c:219-241`). A library should surface "not ready yet" to its caller
and let the caller decide how to wait, not sleep on its behalf.

### D12 — Build hygiene

`CMakeLists.txt:18-20` and `container_baseline_impl/CMakeLists.txt:9-11` both do:

```cmake
set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread"
)
```

This **overwrites** rather than appends, discarding whatever optimisation and hardening flags the
parent project set — so this module may build with different `-O`/`-D_FORTIFY_SOURCE`/stack-protector
settings than the rest of the agent. Use `string(APPEND CMAKE_CXX_FLAGS " …")` or, better,
`target_compile_options`.

Both files also use `file(GLOB …)` for sources, which does not re-run on file addition — a known
CMake anti-pattern that produces confusing incremental-build failures. And `src/Makefile` has no
`container_baseline` entry, so `libcontainer_baseline.so` has no explicit install rule.

### D13 — Test coverage inverted against risk

1,232 lines of unit tests cover the *parsers* well — `ParsePasswdLine`, `ParseApkBlock`,
`DecodeHexAddress`, `ParseOsReleaseLine`, `ParseUnitFile`, `CoresFromCpuMax`, hash vectors, a real
temp-tree walk. That is the low-risk, high-determinism half.

Untested: **`container_baseline_scanner.cpp`** (the orchestrator), `process_scanner.cpp`, the C API in
`container_baseline.cpp`, and both consumer integrations (`grep -rln 'container_baseline|scanContainerBaseline' src/unit_tests/` → nothing).

Every finding in [03](03-findings-correctness.md) and [04](04-findings-performance.md) of severity
"high" lives in the orchestrator or the consumers. The one file with no test is the one that holds
all the lifecycle, scaling and delete-semantics logic.

The `qa/m4..m6_runner.cpp` harnesses are real and useful, but they are compiled by copy-pasting a
`g++` line out of a header comment, require a live container id as `argv[1]`, and are not wired into
ctest — so they cannot guard against regression.

**Recommendation:** inject the container-discovery and PID-resolution seams (`IContainerSource`,
`IPidIndex`) so the orchestrator can be tested against fakes. That is the same seam the concurrency
and caching work needs, so it pays for itself twice.

---

## Reuse summary

| Reimplemented here | Reuse instead | Location |
| --- | --- | --- |
| `HashFile()` triple digest + cap | `OS_MD5_SHA1_SHA256_File(...)` | `shared/os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h:19` |
| (missing) walker rate limit | `check_max_fps()` + `syscheck.max_files_per_second` | `syscheckd/src/run_check.c:462`; decl `syscheck.h:201` |
| (missing) filesystem-type skip | `HasFilesystem(path, syscheck.skip_fs)` | `syscheckd/src/file/file.c:962` |
| Walk recursion + depth + symlink policy | `fim_checker` / `fim_directory` / `fim_file` | `syscheckd/src/file/file.c:893`, `:999`, `:1066` |
| Whole-row `dump()` checksum | FIM's explicit-allowlist checksum | `syscheckd/src/file/file.c:712` |
| `/proc/net/*` row parsing | `PortImpl` + `LinuxPortWrapper` | `data_provider/src/ports/portLinuxWrapper.h` |
| socket-inode → pid/name | `portProcessInfo(procPath, inodes)` | `data_provider/src/sysInfoLinux.cpp:404` |
| `ifaddrs*` → interface JSON | `NetworkLinuxInterface` + `FactoryLinuxNetwork` | `data_provider/src/network/networkLinuxWrapper.h:192,256` |
| dpkg driver loop | `getDpkgInfo(libPath, cb)` | `data_provider/src/packages/packageLinuxDataRetriever.h:39` |
| container `/etc/passwd` read | `UsersProvider` + rootfs-prefixing `ISystemWrapper::fopen` | `users_linux.hpp:33`, `isystem_wrapper.hpp:30` |
| (missing) bounded concurrency | `Utils::AsyncValueDispatcher` (or `AsyncDispatcher` for `rundown()`) | `shared_modules/utils/asyncValueDispatcher.hpp:46`; `threadDispatcher.h:70` |
| (missing) volatile-field suppression | `options.ignore` / `SyncRowQuery::ignoreColumn` | `dbsync/src/sqlite/sqlite_dbengine.cpp:175`, `:1596`; `dbsync.cpp:1095` |
| FS test doubles | `IFileSystemWrapper` + `MockFileSystemWrapper` | `file_helper/filesystem/include/ifilesystem_wrapper.hpp:14` |

The pattern is consistent: **the mechanism-specific parts of this module are genuinely new and were
worth writing; the generic parts were not.** Roughly 700 of the 2,151 implementation lines have a
direct in-tree equivalent.
