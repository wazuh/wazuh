# 04 — Performance and scaling findings (multiple containers)

The module is correct-ish at N=1 and degrades badly as N grows. Every cost below is **linear or
worse in container count**, and the two largest are avoidable outright.

Reference node used throughout: **100 containers, ~2,000 host processes, ~300 inventory rows and
~2,000 monitored files per container** — a mid-size Kubernetes worker.

---

## P1 — The `/proc` sweep storm: O(N_containers × N_processes)

**Severity: high.** `pid_resolver.cpp:60-82`

`ResolvePidsForContainer` walks **all** of `/proc`, opens and reads `/proc/<pid>/cgroup` for every
PID, and runs `std::regex_match` on each cgroup leaf — to find the PIDs of **one** container:

```cpp
DIR* d = ::opendir("/proc");
while (auto* ent = ::readdir(d)) {
    if (!IsAllDigits(ent->d_name)) continue;
    const std::string cg_path = ReadProcCgroupV2Path(pid_str);      // open + read per PID
    if (ExtractContainerIdFromCgroupPath(cg_path) != container_id) continue;   // 2 std::regex
    out.push_back(...);
}
```

It is called **three times per container** on the Syscollector path — once by the orchestrator
(`container_baseline_scanner.cpp:333`), once inside `ScanContainerProcesses`
(`process_scanner.cpp:124`), once inside `ScanContainerNetwork` (`network_scanner.cpp:180`) — and once
per container on the FIM path.

So a Syscollector scan performs **3N full `/proc` walks**: 300 walks × 2,000 PIDs =
**600,000 `open`+`read`+parse operations, plus 1.2 million `std::regex_match` executions**, to
recover information the process already had.

### Measured

Micro-benchmark of the verbatim implementation vs. a single shared sweep
(`scratchpad/bench_resolver.cpp`, `-O2`, warm cache, 68 PIDs on the dev box):

```
host processes visible        : 68
one full /proc sweep          : 0.63 ms   (0.0093 ms/proc)
one-sweep shared index        : 0.26 ms   (built ONCE for all containers)

-- extrapolated to 100 containers, 3 sweeps/container --
current design  : 300 sweeps  =>  188.8 ms
shared index    :   1 sweep   =>    0.3 ms
```

At the reference node's ~2,000 PIDs this scales to roughly **5–6 seconds of pure `/proc` parsing per
Syscollector scan**, none of which produces a single row of output. The structural reduction is
**300×** (300 sweeps → 1).

### Why it is entirely avoidable

`container_instances` already resolves containers **by walking `/proc/<pid>/cgroup` itself** — and
discards the PID. Its `CgroupEntry` carries the data:

```cpp
struct CgroupEntry {
    std::string   containerId;
    std::uint64_t inode{0};
    RuntimeHint   hint{RuntimeHint::unknown};
    std::string   cgroupPath;      // used internally, never published
};
```

`cgroupPath` never reaches `ContainerRecord`, and `pid` is not a field at all. The baseline module's
own header admits the duplication (`pid_resolver.hpp:12-27`: *"This is the reverse of
container_instances' cgroup resolution path (which maps container_id → cgroup_id but discards the PID
along the way)"*).

**Fix, in order of preference:**

1. Add `pid` (and `cgroupPath`) to `ContainerRecord` and to the wire record. Both changes are additive
   and backward-compatible (`ContainerRecordPtr` is `shared_ptr<const>`; the wire format is JSON).
   The baseline then does **zero** `/proc` walks.
2. Failing that, read `/sys/fs/cgroup/<cgroupPath>/cgroup.procs` — O(1) per container instead of O(P).
3. At minimum, build **one** `cgroup-leaf → [pids]` index per baseline run and pass it to every
   scanner. This alone removes 299 of the 300 sweeps and requires no cross-module change.

Also replace the two `std::regex_match` calls with plain prefix/suffix string checks — the patterns
(`docker-<hex>.scope`, `<hex>`) need no regex engine, and they run once per PID per sweep.

---

## P2 — N+1 IPC round-trips for data the first reply already contained

**Severity: high.** `container_baseline_scanner.cpp:143-176`

```cpp
std::vector<ContainerRef> refs = client.listContainers();
for (const auto& ref : refs) {
    const auto lookup = client.resolveByCgroupId(ref.cgroupId, ref.containerId);   // N round-trips
    ...
}
```

The server's `list` reply **already contains the complete record for every container** — runtime,
name, image, digest, labels, network, `oci_mounts`, and the whole Kubernetes block
(`wire_protocol.hpp:221-231` → `recordToJson`). But `ContainerInstancesClient::listContainers()`
throws all of it away, keeping only `runtime`, `container_id`, `cgroup_id`.

The result is `1 + N` round-trips where 1 suffices. Each round-trip is its own AF_UNIX **connect →
send → read → close** (`container_instances_client.hpp:132-200`: no connection reuse, no pipelining),
against a server with **2 worker threads** and a **1,000 ms** client timeout. At N=100 that is 101
connections per baseline, per consumer, serialised behind two workers — and any container in the
`pending` cold-resolve path burns up to ~600 ms of server-side `RetryPolicy` sleep while holding one
of the two workers.

Both consumers do this independently, so a node runs it twice (syscheckd once at startup,
modulesd every interval).

**Fix:** parse `containers[]` from the existing `list` reply into `ContainerContext` directly. This is
a change to the *client header only*, deletes the per-container `resolve` loop, and collapses
1+N round-trips to 1. No protocol change, no server change.

---

## P3 — The container context blob is duplicated into every single row

**Severity: high.** `baseline_rows.cpp:451-457`, `container_baseline_scanner.cpp:340`

Every dbsync row carries the serialised container context as a **string column**:

```cpp
nlohmann::json DbsyncRowBase(const std::string& container_id, const std::string& container_json)
{
    nlohmann::json row;
    row["container_id"]   = container_id;
    row["container_json"] = container_json;      // full context blob, per row
    return row;
}
```

The blob holds id, name, runtime, image, digest, **all labels**, restart count, the network array,
the full `oci_mounts` array, and — for Kubernetes — namespace, pod, node, **all annotations** and the
ownerReferences chain. Kubernetes annotations routinely include
`kubectl.kubernetes.io/last-applied-configuration`, which is itself a full serialised manifest;
1–4 KB per blob is typical and 10 KB+ is not unusual.

| | Rows | × blob | Duplicated bytes |
| --- | --- | --- | --- |
| Syscollector, per scan | 100 × 300 = 30,000 | 1.5 KB | **~45 MB** |
| FIM, per run (2,000 files/container) | 100 × 2,000 = 200,000 | 1.5 KB | **~300 MB** |

That volume is paid **four times over**: built once per container (good), then copied into every row's
JSON, then stored in the DB for every row, then **re-parsed per row on every event emission** —
`syscollectorImp.cpp` parses `container_json` inside `ecsData()` for each row it emits, and FIM's
bridge does the same in `fim_persist_baseline_row`.

The stated justification is *"so DELETED events stay self-contained"* — a real requirement, since a
deleted container's context must survive its removal. But per-row duplication is the most expensive
possible way to meet it.

**Fix:** store the context **once per container** in a dedicated container dimension row/table and
have rows reference `container_id` only. To keep DELETE events self-contained, retain the dimension
row until the last referencing row is deleted (a refcount or a `deleted_at` tombstone with the same
60 s grace `container_instances` already uses). Cache the *parsed* blob per container per scan so
`ecsData` parses it once, not 30,000 times — that alone is a large CPU win with no schema change.

---

## P4 — The entire baseline is buffered in RAM before the first row is written

**Severity: high.** `container_baseline_fim.cpp:144-159`, `syscollectorImp.cpp:1902-1957`

Both consumers accumulate everything, then write.

FIM buffers serialised strings:

```cpp
std::map<std::string, std::vector<std::string>> container_rows;
cbaseline_run_fim_dbsync(..., dbsync_sink, &sink_ctx);   // fills the whole map
...
for (const auto& [container_id, rows] : container_rows) { sync_container(container_id, rows); }
```

Syscollector buffers parsed `nlohmann::json` — several times heavier per byte than the text:

```cpp
using BaselineRows = std::map<std::string, std::map<std::string, nlohmann::json>>;
BaselineRows baseline;
const int baselined = cbaseline_run_syscollector_dbsync(..., sink, &baseline);
```

Underneath, the scanner *also* buffers: `WalkContainerPath` returns a complete
`std::vector<FileBaselineRow>` per path, and every `Scan*` returns a full vector, so a container's
rows exist twice concurrently.

| Scenario | FIM peak buffer | Note |
| --- | --- | --- |
| 100 × 1,000 files | ~200 MB | conservative |
| 100 × 2,000 files | ~400 MB | reference node |
| 100 × 20,000 files (the configured cap) | **~4 GB** | the cap the code actually permits |

The `max_files = 20000` default is per **path**, and multiple paths multiply it — so the configured
ceiling permits an OOM on a normal node. On the FIM side this happens on syscheckd's `main()` thread
during startup.

Per row, FIM also does: parse → `dump()` for the checksum → `dump()` again for storage — three JSON
operations on top of the one the module already performed, and the row is held as a string
throughout.

**Fix:** stream. The sink callback already exists and is invoked per row — open the per-container
scoped transaction **before** scanning that container, feed rows into it as they arrive, and commit
per container. Peak memory becomes O(one row), not O(entire node). This requires inverting the loop
so the container is the outer unit of work on the consumer side too, which is also what P6 needs.

---

## P5 — No concurrency anywhere, and the cold-start storm is unbounded

**Severity: high (NFR3 violation).** `container_baseline_scanner.cpp:306`, `:332`

Every container is scanned strictly serially:

```cpp
for (const auto& identity : DiscoverContainers(connector_socket_path)) { ... }
```

`<thread>` appears in the orchestrator only for `std::this_thread::sleep_for`. The issue asks for a
*"serialize / bounded worker pool"* and a measurement of *"wall-clock to 'node fully baselined'"*.
Neither exists, and the work is I/O-bound — the case that benefits most from bounded parallelism.

Worse, both call sites run on threads that other work depends on:

- **FIM** runs on syscheckd's `main()` thread, before `realtime_start()`. Startup is blocked for the
  whole scan plus fixed sleeps of up to **5 s** waiting for the IPC socket
  (`container_baseline_fim_bridge.c:219-241`) plus up to another **5 s** of empty-list retries
  (`container_baseline_scanner.cpp:38-39`) — ~10 s of pure sleeping before any useful work, then
  minutes of walking and hashing.
- **Syscollector** runs on the scan thread as the last item of `scan()`, delaying every other
  module's scan completion, hourly.

There is no cap on containers baselined per cycle, no total time budget, no CPU or IO rate limit, and
no `nice`/`ionice` equivalent. NFR3's *"must be throttled and limited so it does not stall the agent
or the node"* is unmet in every respect except the two per-path caps.

**Fix:** a bounded worker pool (2–4 threads, configurable) over containers, on a **dedicated thread**
in both consumers, with a per-cycle deadline and a rows-per-second budget. Reuse the existing
`src/shared_modules/utils` dispatcher primitives rather than hand-rolling. Under a deadline, scan
containers in a rotating order so a node too large to fully baseline in one cycle still converges
instead of starving its tail.

---

## P6 — No image-digest de-duplication: the single largest available saving, never attempted

**Severity: high (missed optimisation).** Architectural.

Four of the eleven data classes read **immutable image content** and nothing else:

| Class | Source | Varies per container instance? |
| --- | --- | --- |
| Packages | rootfs dpkg/rpm/apk DB | **No** — image layer content |
| Users / Groups | rootfs `/etc/passwd`, `/etc/group` | **No** |
| OS | rootfs `/etc/os-release` | **No** |
| Services | rootfs systemd unit files | **No** |

For a Deployment with 20 replicas of one image, the module parses the **same** package database 20
times, copies the **same** rpmdb to `/tmp` 20 times, and re-reads the same `/etc/passwd` 20 times —
per scan, every scan. Only the writable upper layer and mounts genuinely differ.

Package scanning is the most expensive of the four: `ScanContainerPackages` copies the entire rpmdb
(tens of MB on a full RHEL image) to a temp dir on **every call for every container**
(`package_scanner.cpp:63-94`), then parses every package header.

The issue names this explicitly: *"can a baseline be skipped or made incremental when a container is
a replica of an already-baselined image (same image digest, immutable layers → only the writable
upper layer + mounts differ)? Potentially large saving."* It was never attempted, and
`image_digest` — the exact key needed — is already carried in `ContainerContext`.

**Fix:** cache image-derived rows keyed by `image_digest`, scan once per distinct digest per cycle,
and stamp the cached rows with each container's identity on emission (`ApplyIdentity` already does
exactly this stamping). On a typical node where 100 containers run 15 distinct images, this is a
**~85% reduction** in package/user/group/OS/service scan work. Correctness caveat: a container can
modify these files in its writable layer, so the cache must be invalidated by the upper layer's
mtime or accepted as a documented, configurable trade-off.

---

## P7 — Hashing cost is 3× larger than any configuration requires

**Severity: medium.** `hash_helper.cpp:44-71`

`HashFile` unconditionally computes **md5, sha1 and sha256** in one pass:

```cpp
EVP_DigestInit_ex(md5_ctx.get(),    EVP_md5(),    nullptr);
EVP_DigestInit_ex(sha1_ctx.get(),   EVP_sha1(),   nullptr);
EVP_DigestInit_ex(sha256_ctx.get(), EVP_sha256(), nullptr);
```

The issue specifies *"content hash (md5/sha1/sha256 **per config**)"*, and host FIM has exactly that
config surface (`CHECK_MD5SUM` / `CHECK_SHA1SUM` / `CHECK_SHA256SUM`). The container path ignores it
and always pays for all three. The single-pass structure is good; the missing part is honouring the
flags, which typically reduces digest CPU by ~2/3.

Note also that this is a **fourth** hashing implementation in-tree, parallel to FIM's own — see
[05](05-findings-clean-design.md#d1--a-parallel-hashing-implementation).

---

## P8 — Per-file syscall and DBSync transaction overhead

**Severity: medium.**

**Double `lstat` per entry** — `rootfs_file_walker.cpp:110-127` then `:68-69`. Every directory entry
is `lstat`ed when discovered, pushed onto the deque, then `lstat`ed **again** when popped. That is 2×
the stat syscalls for the whole tree; `d_type` from `readdir` plus a single `lstat` would do.

**Unbounded deque growth** — the `max_files` cap is only checked when *popping* a file
(`:74-77`) and after finishing a directory (`:131-134`), so the pending deque can accumulate an
entire large directory tree in memory before the cap ever triggers.

**Transaction count** — Syscollector opens a scoped DBSync transaction per (container × table)
**unconditionally**, for all 11 tables even when a container produced no rows for a table
(`syscollectorImp.cpp:1965-1978`), then runs 11 full `SELECT container_id … WHERE container_id != ''`
scans for the stale sweep, then 11 more empty transactions per stale container. At 100 containers:
**1,100 transactions + 11 full-table scans per scan interval**, most of them empty.

**FIM's stale sweep loads the whole table** — `fim_db_get_every_element("file_entry", "WHERE
container_id != ''")` materialises **every container file row** as cJSON purely to collect the
distinct `container_id` set (`container_baseline_fim.cpp:163`). At 200,000 rows this is hundreds of MB
of cJSON for information a `SELECT DISTINCT container_id` returns in microseconds. The Syscollector
side already does it correctly with a projected `SelectQuery`.

---

## P9 — Summary: cost model and the reductions available

Per Syscollector scan interval, reference node (100 containers, 2,000 PIDs, 300 rows/container):

| Cost | Current | After fixes | Reduction |
| --- | --- | --- | --- |
| `/proc` sweeps (P1) | 300 sweeps ≈ 5–6 s | 0 (PID from `container_instances`) or 1 sweep | **~300×** |
| IPC round-trips (P2) | 101 connections × 2 consumers | 1 connection | **~100×** |
| Duplicated context bytes (P3) | ~45 MB/scan | ~150 KB (one row per container) | **~300×** |
| Peak buffered memory (P4) | 400 MB – 4 GB | O(one row), streamed | **bounded** |
| Image-derived scan work (P6) | 100 rootfs parses | ~15 (one per digest) | **~7×** |
| Digest CPU (P7) | md5+sha1+sha256 always | per config | **up to 3×** |
| `stat` syscalls in walk (P8) | 2 per entry | 1 per entry | **2×** |
| DBSync transactions (P8) | ~1,100 + 11 table scans | ~300 non-empty + 1 `SELECT DISTINCT` | **~4×** |
| Container scan concurrency (P5) | 1 | bounded pool (2–4) | **2–4×** wall-clock |

None of these require a new dependency, a schema redesign, or a change of mechanism. P1, P2, P3 and
P4 together are the difference between a feature that is viable at 100 containers per node and one
that is not — and all four are consequences of the same structural choice: **the container is not the
unit of work.** The orchestrator loops over containers but the *consumers* loop over the fully
materialised result, so nothing can be streamed, cached per container, or parallelised. Fixing that
inversion, described in [06-proposed-architecture.md](06-proposed-architecture.md), resolves most of
this list at once.
