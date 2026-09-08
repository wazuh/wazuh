# 01 — What was actually built

Branch: `spike/container-instance-and-fim-syscollector-baseline`
Base: `631afacfc2` (main) → HEAD `66301af90d`
Analysed: 2026-09-02

## 1.1 Scope of the branch

The branch contains two distinct bodies of work. Only the second is #37532.

| Area | Files | Relation to #37532 |
| --- | --- | --- |
| `src/wazuh_modules/container_instances` | ~60 | #37203-1 (identity/metadata). Consumed by, not part of, #37532. |
| `src/wazuh_modules/container_baseline` | 53 | **#37532 proper.** |
| `src/syscheckd/src/ebpf/container_baseline_fim*` | 4 | #37532 FIM consumer. |
| `src/wazuh_modules/syscollector` (modified) | 4 | #37532 Syscollector consumer. |
| `src/shared_modules/dbsync`, `src/syscheckd/src/db` (modified) | 9 | Scoped-transaction support enabling the above. |

`container_baseline` is 5,894 lines: 2,151 lines of implementation, 1,232 lines of unit tests,
477 lines of throw-away QA harnesses (`qa/m4..m6_runner.cpp` + `m4..m6_verify.py`), the rest headers
and CMake.

## 1.2 The mechanism that was chosen

The module answers the spike's central question — *"from where, and by what mechanism, does the agent
read this initial state for a running container?"* — with a single, consistent answer:

> **Address the container through `/proc/<pid>/root/<path>` and `/proc/<pid>/net/*`, using a live PID
> inside the container.**

This is the issue's Angle 1 variant ("`/proc/<pid>/root/<path>` as an alternative addressing scheme")
plus Angle 2 (`/proc`-based inventory). It is a defensible and, in my assessment, the *correct*
primary choice: the kernel performs the mount-namespace translation, so there is no overlay
arithmetic, no per-runtime snapshot-layout knowledge, and bind mounts / volumes / configMap tmpfs are
resolved for free. Docker, containerd and CRI-O are covered by one code path.

Two data classes deviate from pure host-side reads:

- **Interfaces / addresses** (`interface_scanner.cpp:145-163`) enter the container's *network*
  namespace with `setns(CLONE_NEWNET)` on a throw-away thread, then call `getifaddrs()` — because
  sysfs and netlink answer for the caller's netns and have no `/proc/<pid>/`-relative view.
- **Hardware** (`hardware_scanner.cpp:90-119`) reads the container's cgroup v2 resource envelope from
  the *host's* `/sys/fs/cgroup/<path>`, not the container at all.

## 1.3 Module structure

```
container_baseline/
├── include/container_baseline.h          C API: 5 entry points, 3 callback typedefs
├── src/container_baseline.cpp            extern "C" → C++ shims (106 lines)
└── container_baseline_impl/
    ├── include/  (15 headers)
    ├── src/
    │   ├── container_baseline_scanner.cpp   orchestrator (418 lines)
    │   ├── baseline_rows.cpp                row → JSON serialisers (652 lines)
    │   ├── pid_resolver.cpp                 container_id → PIDs via /proc sweep
    │   ├── rootfs_file_walker.cpp           FIM walk + hashing
    │   ├── hash_helper.cpp                  md5+sha1+sha256 via OpenSSL EVP
    │   └── {process,network,user,package,os,interface,protocol,service,hardware}_scanner.cpp
    └── tests/  (12 gtest files)
```

### Data-class coverage

Eleven inventory classes plus FIM files — materially broader than the issue asked for. The issue's
minimum was FIM files, processes, network, and "depending on the #37203-4 coverage decision"
users/groups and packages/OS. Delivered additionally: interfaces, network addresses, protocols
(default routes), systemd services, and virtual hardware.

| Class | Source | Index / dbsync table |
| --- | --- | --- |
| FIM files | `/proc/<pid>/root` walk + hash | `wazuh-states-fim-files` / `file_entry` |
| Processes | `/proc/<pid>/{stat,cmdline}` | `…-inventory-processes` / `dbsync_processes` |
| Ports | `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` + fd→inode map | `…-inventory-ports` / `dbsync_ports` |
| Users / Groups | rootfs `/etc/passwd`, `/etc/group` | `…-inventory-users` / `-groups` |
| Packages | rootfs dpkg / dpkg `status.d` / apk / rpm (sqlite + BDB) | `…-inventory-packages` |
| OS | rootfs `/etc/os-release` + host `uname()` | `…-inventory-system` |
| Interfaces / Addresses | `setns` + `getifaddrs()` | `…-inventory-interfaces` / `-networks` |
| Protocols | `/proc/<pid>/net/route` (IPv4 default only) | `…-inventory-protocols` |
| Services | rootfs systemd unit files | `…-inventory-services` |
| Hardware | host `/sys/fs/cgroup/<path>` + `/proc/cpuinfo` | `…-inventory-hardware` |

Genuinely strong work sits in the package scanner (`package_scanner.cpp`): it reuses sysinfo's
header-only `parseDpkg`/`parseRpm` helpers without linking libsysinfo, handles the distroless
`/var/lib/dpkg/status.d` layout, and solves a real problem — sqlite canonicalises away the
`/proc/<pid>/root` magic symlink, so the rpmdb is copied to a private temp dir before opening
(`package_scanner.cpp:63-94`). That analysis is correct and non-obvious.

## 1.4 Output shapes: two parallel, undecided paths

Every data class has **two** serialisers and every scan entry point has **two** variants:

| | Sync-protocol shape | Raw dbsync shape ("Option A") |
| --- | --- | --- |
| Builders | `BuildProcessJson`, … (12) | `BuildProcessDbsyncRow`, … (12) |
| FIM entry | `cbaseline_run_fim` | `cbaseline_run_fim_dbsync` |
| Syscollector entry | `cbaseline_run_syscollector` | `cbaseline_run_syscollector_dbsync` |

Both consumers use **only** the `_dbsync` variants. The sync-protocol path
(`cbaseline_run_fim`, `cbaseline_run_syscollector`, and all 12 `Build*Json` functions) has **no
caller anywhere in the tree** — it is dead code carrying a self-documented schema caveat
(`baseline_rows.hpp:59-64`: *"draft ECS-ish shape … not a byte-for-byte reproduction of
`Syscollector::ecsData()`"*). Option A won; Option B was never removed.

## 1.5 How the consumers drive it — the decisive finding

The two consumers picked **opposite and mutually inconsistent** execution models, and neither is the
model #37532 describes.

### FIM — one shot, at startup, on the main thread

`src/syscheckd/src/main.c:308-318`:

```c
    fim_initialize();

#ifdef __linux__
    if (!syscheck.disabled) {
        fim_run_container_baseline();
    }
#endif

    if (!syscheck.disabled && start_realtime == 1) {
        realtime_start();
    }
```

- Runs **once per agent lifetime**, synchronously, blocking `main()`.
- Runs **before `realtime_start()`** — i.e. scan-then-subscribe, the one ordering the issue
  identifies as *"risk missing changes during the scan"* (§6).
- Containers created after agent start are **never** FIM-baselined.

`container_baseline_fim.cpp:131-185` then does three phases: buffer every row for every container in
memory → per-container scoped DBSync txn → stale-container sweep via
`fim_db_get_every_element("file_entry", "WHERE container_id != ''")`.

### Syscollector — full re-scan on every scan interval

`syscollectorImp.cpp:2081-2088`:

```cpp
    // Container baseline (#37532) now runs every scan interval, same as the
    // host scans above: … No separate interval/config — it rides scan()'s own.
    TRY_CATCH_TASK(scanContainerBaseline);
```

`scanContainerBaseline()` (`syscollectorImp.cpp:1898-2030`) re-scans **all eleven data classes for
every container** on every syscollector interval, buffers everything, then runs 11 scoped DBSync
transactions per container plus a stale sweep of 11 `selectRows` full-table scans.

The syscollector integration is the better-engineered of the two: it calls
`cbaseline_list_containers` to distinguish "stopped" from "gone" (`:1975-1988`), and it has a
first-sync-quiet guard so a container's seed does not raise stateless alerts
(`m_knownContainerIds`, `:1961-1963`). FIM's integration has neither.

### Why this matters

The spike's premise is: **a baseline seeds state once, and the eBPF change stream maintains it.**
What was built is a *periodic full inventory poller* on one side and a *one-shot startup seed* on
the other. Under the syscollector model the eBPF stream is largely redundant for those eleven
classes; under the FIM model the baseline is never refreshed and misses every container that starts
later. Neither consumer has any coordination with the eBPF event stream at all — see
[07-options-matrix.md](07-options-matrix.md) and [06-proposed-architecture.md](06-proposed-architecture.md).

## 1.6 Testing

- 12 gtest files, 1,232 lines — good coverage of the *parsers* (`ParsePasswdLine`, `ParseApkBlock`,
  `DecodeHexAddress`, `ParseOsReleaseLine`, `ParseUnitFile`, `CoresFromCpuMax`, `IsOverlayWhiteout`,
  hash vectors, `rootfs_file_walker` against a temp tree).
- **No test exists for** `container_baseline_scanner.cpp` (the orchestrator), `process_scanner.cpp`,
  or the C API in `container_baseline.cpp`. The orchestrator is where every scaling and lifecycle
  defect in this analysis lives; it is the one file with no unit test.
- `qa/m4..m6_runner.cpp` are hand-run harnesses requiring a live container id, compiled by a
  copy-pasted `g++` line in a header comment. They are not wired into ctest and cannot run in CI.

## 1.7 Documentation delivered

```
$ git diff --stat 631afacfc2..HEAD -- '*.md'
(no output)
```

**Zero.** #37532 is a research spike whose acceptance criteria are eight documents (options matrix,
per-runtime rootfs resolution note, host-side baseline design, handoff algorithm, timing model,
in-container-exec evaluation, cost & limits report, Docker-parity/edge-case table). The branch
delivered ~2,150 lines of production-shaped C++ and no analysis document. There is no `37532` string
in any `.md` file in the repository.

This is the single largest gap against the issue, and it is not a formality: the undocumented
decisions (why `/proc/<pid>/root` over overlay math, why `setns` is acceptable under a
"no-in-container-execution" constraint, what the throttle defaults should be) are exactly the ones a
reviewer needs to sign off, and several of them turn out to be wrong or unmade. See
[02-requirements-gap.md](02-requirements-gap.md).
