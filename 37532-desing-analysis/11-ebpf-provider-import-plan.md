# 11 — `ebpf_provider` import plan and the baseline↔eBPF handoff

Roadmap [item 21](08-roadmap.md#p2--architecture-make-it-a-baseline) — *"implement the handoff algorithm: subscribe-first, scan, reconcile-by-re-read"* — was recorded as **blocked on #37203-2's event contract and overflow signal** ([09](09-implementation-status.md#not-done--deliberately-deferred)). That contract now exists: #37396's spike extracted all eBPF logic out of syscheckd into `src/shared_modules/ebpf_provider/`, with a versioned event struct and an in-band drop flag.

This document does two things. **Part A** plans the import of that provider onto `37532-5-0-0-container-integration`. **Part B** re-derives [06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff)'s handoff algorithm against the provider's *real* contract rather than the sketch's assumptions — because three of the sketch's premises (per-container subscription, per-container drop signalling, an engine-supplied sequence number) do not exist in the code, and one of its steps is actively unsafe.

**Verdict up front:** item 21 moves from *blocked* to *unblocked with three provider gaps*. The algorithm is implementable, the re-read decision is not just validated but forced, and the import is low-risk if done in the order below. But the provider as written delivers a **whole-host firehose** of 12 KB events into an 8 MiB buffer with **no in-kernel filter and no per-container loss attribution**, and that — not the event contract — is what decides whether the handoff converges or thrashes.

---

## 11.1 Which version to import, and why not the one named

### The commit named in the request is a non-working intermediate

`2676bb86c80f39b0d7c7e4884a60925f2bd9ca52` ("feature: added new ebpf module") adds the seven provider files, but two later commits on the same branch rewrite them:

| Commit | Effect on `src/shared_modules/ebpf_provider/` |
| --- | --- |
| `2676bb86c8` | Adds the 7 files. `rt_engine.c` 245 lines; `RT_ABI_MINOR 0`; `rt_filter` has **no** `bpf_obj_path`. |
| `0ce0c2fbc0` "integrate new ebpf module to fim" | Rewrites 150 of `rt_engine.c`'s lines, +50 in `rt_file.bpf.c`, +10 in `rt_engine.h`, +13 in `rt_event_contract.h`. Adds `rt_filter::bpf_obj_path` and bumps to `RT_ABI_MINOR 1` (adds `cwd`/`parent_cwd`/`parent_comm`). Also cuts `ebpf_whodata.cpp` over to the provider (−508 lines) and registers the subdirectory in `src/CMakeLists.txt`. |
| `9113442eb4` "test related to whodata" | Adds `POSITION_INDEPENDENT_CODE ON` to `rt_engine`; **deletes** `modern.bpf.c` (1054 lines) and `modern-arm.bpf.c` (495); removes the `libbpf_external` block from `src/external/CMakeLists.txt`; repoints `inst-functions.sh` to `build/lib/rt_file.bpf.o`. |

`git log --all --oneline -- src/shared_modules/ebpf_provider` returns exactly those three commits and nothing else. So `9113442eb4`'s tree **is** the canonical, latest form of the extraction — no later commit on `spike/37533-fim-ebpf-integration` or `spike/37533-37534-fim-syscollector-ebpf-integration` touches it.

Taking `2676bb86c8` alone would import a provider that (a) can only find its BPF object relative to the process CWD — wrong for a systemd-managed agent, as the header's own comment says (`rt_engine.h:38-45` at `9113442eb4`); (b) drops `cwd`/`parent_cwd`/`parent_comm`, without which host whodata's "who" attribution regresses; (c) has no PIC, so linking `rt_engine` into the `fimebpf` shared library fails outright.

**Decision: import the tree at `9113442eb4:src/shared_modules/ebpf_provider/`.** Ruled out: `2676bb86c8` (incomplete, per above); merging all three commits' *code* changes (drags in the whodata cutover — see §11.7).

### The other two branches are the design record, not the implementation

- `enhancement/37396-ebpf-provider-spike` contains one commit, `1ef4b9ad78` "docs(spike): eBPF runtime-telemetry provider spike (#37396)" — 24 files under `spike-37396/` (peer research, event-contract spec, lifecycle/backpressure, compatibility matrix, ADR-001..003, per-distro evidence files, a standalone PoC). **No `ebpf_provider` code.**
- `remotes/origin/spike/37396-ebpf-module` contains an evidence pack plus `c4af82923f "Add event contract draft v0"`. Also no `ebpf_provider` code.

The provider's own comments cite these as normative (`ADR-001` module boundary, `ADR-002` min-kernel-per-event-class, `ADR-003` serialization/versioning). Read them before changing the contract; do not treat them as an alternative source for the code.

---

## 11.2 The provider's actual contract

### Lifecycle API — three functions, verbatim

```c
typedef void* rt_handle_t;                                                  // rt_engine.h:25
typedef void (*rt_sink_fn)(const struct rt_file_event* ev, void* user);     // rt_engine.h:27

struct rt_filter                                                            // rt_engine.h:29-47
{
    unsigned int type_mask;      /* bitmask of (1u << rt_event_type) */
    const char*  bpf_obj_path;   /* NULL -> "rt_file.bpf.o" in the process CWD */
};

rt_handle_t rt_open(const struct rt_filter* filter);                        // rt_engine.h:66
int         rt_poll(rt_handle_t, rt_sink_fn, void* user, int timeout_ms);   // rt_engine.h:73
void        rt_close(rt_handle_t);                                          // rt_engine.h:77
```

There is no `start`/`stop`/`subscribe`. `rt_open` loads and attaches in one call; `rt_poll` is the only drain; `rt_close` tears down.

### The event — one fixed-size struct, 12,416 bytes

```c
struct rt_file_event                                        // rt_event_contract.h:70-99
{
    unsigned short abi_major;      unsigned short event_type;   /* enum rt_event_type */
    unsigned short flags;          unsigned short _reserved0;   /* enum rt_flags bitmask */
    unsigned long long timestamp_ns;                            /* bpf_ktime_get_boot_ns */
    unsigned int pid, ppid, uid, gid;
    unsigned long long inode, dev;
    unsigned long long cgroup_id;                               /* correlation key */
    unsigned int mnt_ns;                                        /* correlation key */
    unsigned int dropped;                                       /* drop counter at emit time */
    char comm[32];
    char filename[4096];
    char cwd[4096];  char parent_cwd[4096];  char parent_comm[32];   /* MINOR 1 */
};
```

Event classes: `RT_EV_FILE_OPEN=1` (create, or open with write intent), `RT_EV_FILE_ATTR=2`, `RT_EV_FILE_UNLINK=3`, `RT_EV_FILE_RENAME=4` (carries the **destination** path) — `rt_event_contract.h:42-48`.

### Threading and ownership

| Property | Reality | Consequence for item 21 |
| --- | --- | --- |
| Sink thread | `rt_poll` invokes `sink` synchronously on the caller's thread (`rt_engine.c:214-223, 307-317`). | All work in the sink must be non-blocking. The spike learned this the hard way and split off a worker thread — `container_live_fim.h` documents that cgroup→container resolution "can block on IPC for up to ~1s". |
| Event buffer ownership | `sink` receives a pointer into the ring buffer's mapped region, valid only for the callback's duration (libbpf's `ring_buffer_sample_fn` contract). | Must copy. `handle_event()` at `415e7a2204:ebpf_whodata.cpp` copies into `std::string`s. |
| Concurrency | `rt_poll` writes `h->current_sink`/`h->current_user` on every call (`rt_engine.c:314-315`). Header says "not thread-safe to call concurrently on the same handle". | One drain thread per handle, period. |
| Multiple consumers | Each `rt_open` = its own `bpf_object` load, its own attach, its own 8 MiB ring buffer (deliberate, per ADR-001: "no shared provider, no cross-consumer stalling"). | Two consumers double the kernel-side probe cost and memory. Measurable, and a real decision point (§11.7 phase A3). |
| Teardown | **`rt_close` never destroys the `bpf_link`s.** `rt_open` discards `bpf_program__attach`'s return into a local at `rt_engine.c:276-283`; `rt_close` (`:319-335`) frees only `h->rb` and `h->obj`. | Probes stay attached for the process's lifetime; the freed ring buffer keeps being written by still-attached programs (dropping in-kernel); a second `rt_open` **double-attaches** and delivers duplicate events. Must be fixed (§11.9 item 4). |

### Failure and degradation

`rt_open` returns `NULL` — never aborts — on: empty/invalid `type_mask` (`:227-231`), `dlopen("libbpf.so.1")` then `dlopen("libbpf.so")` both failing (`:94-103`), any missing libbpf symbol (`RT_RESOLVE_SYM`, `:74-84`), `bpf_object__open_file` failure i.e. missing `.bpf.o` (`:247-253`), `bpf_object__load` failure (`:260-267` — *this is the capability probe*: no BTF/CO-RE, no `BPF_MAP_TYPE_RINGBUF`, or insufficient privilege all land here), attach failure (`:276-283`), missing `rb` map (`:286-293`), `ring_buffer__new` failure (`:295-302`).

There is deliberately **no kernel-version floor** (see the file header comment, `:27-32`). `is_bpf_lsm_active()` (`:131-155`) reads `/sys/kernel/security/lsm` and picks the `lsm/file_open` variant over `kprobe/vfs_open` when `bpf` is an active LSM (`select_programs`, `:181-212`).

**Every one of those failures logs to `fprintf(stderr)`.** A Wazuh daemon's stderr is not `ossec.log`, so *an eBPF load failure is invisible in the agent log.* This is not hypothetical: the VM validation run (`825214fd61:spike-37533/container-fim-syscollector-test-plan-and-results.md`, step 3.2) found the agent had been silently running the Audit provider the whole time with "nothing in the startup log even mention[ing] eBPF." Needs a log callback (§11.9 item 3).

### Event loss — the property the algorithm turns on

Loss **is** signalled, in band:

```c
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key,__u32); __type(value,__u32);
         __uint(max_entries, 1); } drops_map SEC(".maps");     // rt_file.bpf.c:80-86

statfunc void bump_drop_counter(void)  { ... __sync_fetch_and_add(counter, 1); }   // :90-98
statfunc __u32 take_drop_counter(void) { ... __u32 v = *counter; *counter = 0; return v; }  // :100-111
```

`submit_event` (`:243-300`) increments on `bpf_ringbuf_reserve` failure and, on the next successful submit, drains the counter into `evt->dropped` and sets `RT_F_DROPS_BEFORE` (`:271-275`).

So subscribe-first is **not** unsound for want of loss signalling. But five properties of that signal constrain the design:

1. **The counter is global — one slot, no key.** It cannot answer "was container C's baseline window lossy". [06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff)'s trigger *"#37203-2 signals a ring-buffer drop for C → re-baseline C"* is **not implementable as written**.
2. **Loss is only observable when a later event succeeds.** If the buffer stays full through process teardown, the loss is never reported at all.
3. **`take_drop_counter`'s read-then-`*counter = 0` is not atomic** (`:106-110`) while `bump_drop_counter` is. Concurrent CPUs can lose drop counts — the signal under-reports.
4. **`RT_F_CGROUP_V1` (`rt_event_contract.h:57`) is declared and never set.** `submit_event` sets `flags = 0` (`:256`) and only ever ORs `RT_F_DROPS_BEFORE` (`:274`). A cgroup-v1 host is indistinguishable from v2 in band, even though the header says correlation "must fall back to `mnt_ns`" there.
5. **No consumer reads any of it.** `grep -n "abi_major\|RT_F_\|dropped\|flags"` over `415e7a2204`'s `ebpf_whodata.cpp` and `container_live_fim.cpp`: zero hits. `container_file_event` (`ebpf_whodata.cpp` at `415e7a2204`, ~line 145) copies `filename/cgroup_id/mnt_ns/pid/inode/dev` and drops `event_type`, `flags` and `dropped` on the floor.

There is also **no userspace occupancy metric** — `rt_engine.c`'s `libbpf_api` table (`:53-69`) resolves 13 symbols and `ring__avail_data_size` is not among them — so a consumer cannot throttle *before* overflow, only react after.

### The scale problem, stated numerically

`rb` is `1 << 23` = 8,388,608 bytes (`rt_file.bpf.c:44`). `sizeof(struct rt_file_event)` = 12,416. That is **~675 in-flight events**, and filtering is **100% userspace**: `rt_filter` gates only which *programs* autoload, and the BPF program has no allowlist map, no cgroup check and no path check. Every write-intent `vfs_open`, every `security_inode_setattr`, every `vfs_unlink`, every `vfs_rename` on any regular file **anywhere on the host** is submitted.

Subscribe-first over that, with a ~675-event window and a userspace prefix filter (`matches_container_prefix()`, which walks the configured path list *per event*), is where the algorithm will actually fail in production. §11.9 item 1.

---

## 11.3 What the provider covers — do not overclaim

`rt_event_contract.h:20-22` is explicit: *"Scope for this pass: FILE event classes only… Process-exec and network event classes are a separate issue's scope, not added here."*

Against [07 §7.2](07-options-matrix.md#72-the-matrix)'s eleven data classes and [06 §6.6](06-proposed-architecture.md#66-tiering-the-data-classes-s4)'s tiers:

| 06 §6.6 tier | Class | Provider covers? | Revised tier |
| --- | --- | :-: | --- |
| **Event-maintained** | FIM files | **yes** — open-with-write-intent/create, attr, unlink, rename | **stays event-maintained** |
| **Event-maintained** | processes | **no** — no exec/exit class exists | → **Sampled** (periodic `/proc` rescan, M3) until a process class ships |
| **Event-maintained** | ports | **no** — no socket class exists | → **Sampled** (periodic, M3) |
| Image-derived | packages, users, groups, OS, services | no | unchanged (`ImageContentCache`, item 22, already done) |
| Sampled | interfaces, addresses, protocols, hardware | no | unchanged |

So **one of the three classes 06 assigned to the event-maintained tier can actually hand off today.** That is the single largest correction to 06 §6.6.

Even within files, the coverage has hard edges:

- **Regular files only.** `is_regular_file()` (`rt_file.bpf.c:302-307`) gates every hook. Directories, symlinks, sockets, FIFOs, devices produce no events. (Consistent with `FileBaselineRow`'s own scope, which also skips them.)
- **`FILE_OPEN` fires on write *intent*, not on the write.** `kprobe/vfs_open` (`:310-345`) triggers on `FMODE_CREATED | O_CREAT | O_ACCMODE`, i.e. at open time. There is no close or write event class. A re-read triggered by that event sees the **pre-write** content. Host whodata has the same property; it matters more here because the re-read is container FIM's *only* source of truth.
- **Rename reports the destination only** (`:507-559`), so the source path's row is never retired by the event — it is only cleaned up by a subsequent walk or a re-read of the old path that now fails.
- **`inode`/`dev` are diagnostic.** `container_live_fim.h` says so explicitly: "the authoritative inode for the persisted row comes from `stat()`-ing the resolved host path."
- **Rename is silently broken on one kernel family.** `struct renamedata___local` (`rt_file.bpf.c:498-505`) hardcodes `{mnt_idmap, old_parent, old_dentry, new_parent, new_dentry}`, validated on kernel 7.0.0. The older layout (`{old_mnt_userns, old_dir, old_dentry, new_mnt_userns, new_dir, new_dentry}`) puts `new_dentry` 8 bytes further along. The file's own comment documents that the *previous* struct produced **zero rename events with nothing in any log** on the newer kernel; the imported version has the same failure mode inverted. §11.9 item 8.

**Kata / VM-isolated:** host-side eBPF cannot see in-guest file operations at all. Consistent with [07 §7.2](07-options-matrix.md#72-the-matrix)'s last row and with `container_instances`' `VerdictReason::kata` classification — must be an explicit skip, not an empty result.

---

## 11.4 Container attribution

### What the event gives you

`pid` (a tgid, `rt_file.bpf.c:260`), `ppid`, `cgroup_id` (`bpf_get_current_cgroup_id()`, `:268`), `mnt_ns` (`get_mnt_ns_inum`, `:230-241`), plus `uid/gid/comm/cwd/parent_*`. **No container id** — by design: *"the engine has no idea what a 'container' is, per the consumer-agnostic constraint"* (`rt_event_contract.h:83-85`).

And `filename` is the path **in the writer's own mount-namespace view** — i.e. container-relative (`/etc/passwd`, not `/proc/<pid>/root/etc/passwd` and not the host overlay path). This is documented in `415e7a2204:src/syscheckd/src/ebpf/include/container_live_fim.h` and was validated end-to-end on the VM. Two consequences: the path must be prefixed with `/proc/<pid>/root` to be host-readable (the same M2 addressing the baseline already uses — no overlay maths), and **paths collide totally across containers** (every image has `/etc/passwd`), so attribution must precede any use of the path as a key.

### Resolution: use `ContainerRef::cgroupId`, which already exists

Three options, and the choice matters a great deal:

| Option | Cost per event | Verdict |
| --- | --- | --- |
| Per-event IPC `resolveByCgroupId()` | One `connect/send/recv/close` against a 2-worker server, **up to ~1 s cold** (`container_instances_client.hpp:58-68`) | What the spike does. **Rejected as the steady-state path** — it forces a worker thread (fine) but is unbounded work per event on a whole-host firehose. Keep it only as the cold-miss fallback. |
| Per-event `/proc/<pid>/cgroup` read | one `open`+`read`+parse, per event | **Rejected — a performance disaster**, and usually *impossible* anyway: the VM run found the writer PID is normally **already dead** by processing time (test-plan finding 3b: "essentially always true for shell-triggered writes"). |
| **In-process `cgroup_id → container_id` map from one `list` reply** | one hash lookup, **zero syscalls** | **Chosen.** |

The third option needs nothing new. `ContainerRef` already carries it:

```cpp
struct ContainerRef {                        // container_instances_client.hpp:34-52
    std::string   runtime;
    std::string   containerId;
    std::uint64_t cgroupId {0};              // populated at :118-128 from the list reply
    nlohmann::json record;                   // the FULL record the list reply carried
};
```

One `listContainers()` call yields `{cgroup_id → container_id}` for every container on the node. Refresh it on the item-20 trigger (the 30–60 s `list` poll, or the preferred `watch` op). Cold miss → one asynchronous `resolveByCgroupId` on the worker thread, insert the answer, and **negatively cache `notContainer`** (a permanent verdict per `LookupStatus`, `container_instances_client.hpp:19-26`) so a host process's writes are not re-queried forever.

Then `container_id → pid` for the re-read comes from what already exists: `PidIndex` (`pid_resolver.hpp:23-60`, one `/proc` sweep per run, ascending PIDs so `.front()` is the entrypoint) plus `SelectAddressablePid()` (item 24, commit `d8e4cd5704`), which skips snapshot entries that already exited. Use the **event's own pid as an optimistic first try** and fall straight through to `PidIndex` — every process in a container shares its mount namespace, so any live PID is equally valid (the reasoning `container_live_fim.h` records, and `ResolvePidsForContainer` is already an exported symbol of `libcontainer_baseline.so`).

`container_instances` is also already doing the *other* half of this join internally — `CgroupEntry{containerId, inode, hint, cgroupPath}` and `ICgroupResolver::scanOne(uint64_t cgroupInode)` (`ci_impl/src/cgroup/i_cgroup_resolver.hpp:23-52`), with `InodeReader::inodeOf` (`inode_reader.hpp:13-21`) supplying `st_ino`. So the `cgroup_id == cgroup-dir inode` equivalence the whole scheme rests on is already assumed in-tree; §11.11 flags that it is assumed rather than proven.

### Attribution's blind spots — these define the fallback set

1. **cgroup v1**: `cgroup_id` collapses to a fixed constant (`rt_event_contract.h:52-58`), and the flag that would say so is never set (§11.2). `mnt_ns` is carried but `container_instances` has **no `mnt_ns` index** (`container_live_fim.h`: "not yet used for resolution"). → **On cgroup-v1 hosts the event tier is unavailable and must fall back wholesale to periodic rescan.** A cheap in-branch fix: have the `PidIndex` sweep also `stat("/proc/<pid>/ns/mnt")` and build `mnt_ns → container_id`. That needs no cross-module change and closes the gap for v1 hosts. Recommend it.
2. **kubelet-written mounts** — configMap, secret, downwardAPI, projected. The kubelet performs the atomic symlink swap, so the event carries **the kubelet's cgroup**, resolves `notContainer`, and is dropped. Confirmed as a real, previously-undocumented gap in `825214fd61:spike-37533/volume-type-behavior-matrix.md`. → Those paths **stay on periodic rescan**, permanently, unless a path/mount-based attribution fallback is added.
3. **Host-side writes into a `hostPath`/bind mount**: same shape — `notContainer`, dropped, invisible to container FIM until the next rescan.
4. **PID reuse (TOCTOU)**: the live path checks `access("/proc/<pid>")` and then builds `/proc/<pid>/root/<path>` from that same PID. Nothing verifies the PID still belongs to the *expected* container. Fix by re-deriving via `ExtractContainerIdFromCgroupPath()` on `/proc/<pid>/cgroup` at point of use and comparing — the technique `ResolvePidsForContainer` already implements (`pid_resolver.hpp:75-81`).
5. **`hostPID`/`cgroupns=host`**: the same "correlation key doesn't mean what the code assumes" class; the branch already has `container_scope.{hpp,cpp}` (item 4) for the netns half.

---

## 11.5 Current state on this branch

`src/shared_modules/` contains `agent_metadata, common, container_instances_client, content_manager, dbsync, file_helper, http-request, indexer_connector, keystore, metrics, schema_validator, sync_protocol, uds_http_server, utils` — **no `ebpf_provider`.** Confirmed.

`src/syscheckd/src/ebpf/` today:

```
include/  bounded_queue.hpp  bpf_helpers.h  container_baseline_fim.h
          container_baseline_fim_bridge.h  dynamic_library_wrapper.h
          ebpf_whodata.h  ebpf_whodata.hpp  wrapper_bpf.h
src/      container_baseline_fim.cpp (406)  container_baseline_fim_bridge.c (427)
          ebpf_whodata.cpp (837)  modern.bpf.c  modern-arm.bpf.c
tests/    fimEbpfWhodataTest/ (7 files, 734 lines)  unit/bounded_queue_test.cpp
```

- `fimebpf` is a SHARED library built from `ebpf_whodata.cpp`, `container_baseline_fim.cpp`, `container_baseline_fim_bridge.c`, `../persist_syscheck_msg.c`, linking `wazuh container_baseline` (`src/syscheckd/src/ebpf/CMakeLists.txt:25-28`).
- libbpf is loaded via `so_get_module_handle(LIB_INSTALL_PATH)` where `LIB_INSTALL_PATH` is `"bpf"` (`ebpf_whodata.cpp:31,364`) → `dlopen("libbpf.so")` (`src/shared/src/sym_load.c:22-24`).
- `handle_event()` (`ebpf_whodata.cpp:97-138`) matches via `fim_configuration_directory(e->filename, false)` — a **host** config lookup, which is meaningless against a container-relative path. The spike's version routes container candidates by prefix *before* reaching that call.
- `BoundedQueue<T>` (`include/bounded_queue.hpp`) is pre-existing 5.0.0 machinery: `push()` returns `false` when full, so drop counting is already possible; `FIM_FULL_EBPF_KERNEL_QUEUE` is logged once via a latch (`ebpf_whodata.cpp:127-134`).

### The FIM baseline driver, which the import must not break

`container_baseline_fim.cpp` implements the streaming contract the orchestrator guarantees (rows contiguous per container, then exactly one status):

- `ScopedContainerTxn` — RAII over a scoped `file_entry` transaction keyed on `container_id` (`:123-190`), with `finish(bool detect_deletions)` at `:171-185`: `fim_db_transaction_deleted_rows()` on a complete scan, plain `fim_db_transaction_close()` on a partial one.
- `BaselineDriver::onStatus(id, partial)` (`:220-240`) → `finishCurrent(!partial)`; a complete scan with zero rows still opens a transaction so stored rows age out.
- `sweepStale(known)` (`:246-280`) — ages out only ids absent from `cbaseline_list_containers()`, never merely-stopped ones.

**None of this touches eBPF.** It lives under `src/ebpf/` for historical reasons only ([08 item 31](08-roadmap.md#p3--maintainability): "move the FIM driver out of `src/syscheckd/src/ebpf/` (it has nothing to do with eBPF)"). The import plan below never modifies these two files.

Syscollector's side: `scanContainerBaseline()` (`syscollectorImp.cpp:2087+`), `scopedTxnTables()` (`:247-256`), per-container first-sync quiet guard via `m_knownContainerIds` + `notifyOverride` (`:2185-2201`), stale sweep erasing from `m_knownContainerIds` (`:2077`), invoked **every scan interval** from `scan()` (`:2426`).

### The ordering the algorithm must invert

```
main.c:486    fim_run_container_baseline();     // the walk
main.c:491    realtime_start();
run_check.c:929  w_create_thread(ebpf_whodata); // inside start_daemon(), i.e. later still
```

Scan, *then* subscribe — precisely the losing ordering [06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff) identifies (its `main.c:308-318` reference is now `486/491`). Every change during the walk is lost today.

### Build/test constraints already on record

- WSL cannot reliably build or load real `.bpf.o`; `wazuh_manager` is the VM for that (`/home/rovogel/wazuh/source/.claude/skills/vm-build-test/SKILL.md`: repo at `/home/ubuntu/source/wazuh`, agent at `/var/ossec`, `make build -j$(nproc) TARGET=agent`, `sudo ./install.sh` with a preloaded `etc/preloaded-vars.conf`, `ctest --output-on-failure -R <pattern>` from `src/build`, plus a `rebaseline.sh` helper to force the one-shot container baseline to re-run).
- [09 §Environment notes](09-implementation-status.md#environment-notes-found-while-verifying): `TEST=yes` cannot configure in this WSL environment at all — CMake 4.4.2 dropped compatibility with the vendored googletest's `cmake_minimum_required(VERSION 2.8.12)`. The module's tests were therefore built against a locally compiled gtest.

---

## 11.6 Build integration — the largest single import risk

### How the *current* BPF object is actually produced

This matters more than it looks. `src/external/libbpf-bootstrap/CMakeLists.txt:78-88`:

```cmake
set(WAZUH_BRANCH "v4.12.0" CACHE STRING "Wazuh branch for modern.bpf.c")
set(FILE_URL "https://raw.githubusercontent.com/wazuh/wazuh/${WAZUH_BRANCH}/src/syscheckd/src/ebpf/src/modern.bpf.c")
file(DOWNLOAD ${FILE_URL} ${DEST_PATH})
...
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h/include/${ARCH}/vmlinux.h)
bpf_object(modern src/modern.bpf.c)
```

**The in-tree `src/syscheckd/src/ebpf/src/modern.bpf.c` is not what ships.** The build downloads `modern.bpf.c` from GitHub at tag `v4.12.0` and compiles *that*, against the **portable per-arch header** from `libbpf/vmlinux.h.git` — not the build host's own BTF. And `src/external/CMakeLists.txt:1184-1197` short-circuits the whole thing when a prebuilt object is present (`external/libbpf-bootstrap/build/modern.bpf.o` — 1,000,448 bytes, dated Jul 3, present in this checkout), fetched as a prebuilt external resource by `src/Makefile:496` (`EXTERNAL_RES += … libbpf-bootstrap`).

Two consequences:

1. **The `modern.bpf.c` conflict in `2676bb86c8` is cosmetic.** Nothing in the build reads the in-tree file. Its diff (the `renamedata___local` layout correction) can be dropped from the import entirely — or applied as documentation, knowing it changes no artifact. Do not spend conflict-resolution effort there.
2. **The current agent build needs neither `clang` nor `bpftool` nor readable kernel BTF.** The provider's CMakeLists breaks all three assumptions.

### What the provider's CMakeLists assumes

```cmake
find_program(BPFTOOL_EXECUTABLE bpftool REQUIRED)      # :21
find_program(CLANG_EXECUTABLE   clang   REQUIRED)      # :22
add_custom_command(OUTPUT ${RT_VMLINUX_H}
  COMMAND ${BPFTOOL_EXECUTABLE} btf dump file /sys/kernel/btf/vmlinux format c > ${RT_VMLINUX_H})   # :41-45
add_library(rt_engine STATIC src/rt_engine.c)          # :62
target_link_libraries(rt_engine PUBLIC dl)             # :66   (libbpf is dlopen'd, no -lbpf)
set_target_properties(rt_engine PROPERTIES POSITION_INDEPENDENT_CODE ON)   # :73
if(UNIT_TEST)  # "No unit tests yet for this newly-extracted engine"       # :75-79
```

`REQUIRED` makes a missing `bpftool` a **hard configure-time error for the entire agent build**, and `/sys/kernel/btf/vmlinux` is not readable in a build container. Its own comment concedes the portability cost: *"rt_file.bpf.o is most reliable when built on (or for) the same kernel it will run on; cross-kernel CO-RE portability of the generated header is a real but separate concern."* That is strictly worse than the existing pipeline's portable per-arch header.

Also, `9113442eb4` **deletes** the `libbpf_external` block (`src/external/CMakeLists.txt:1181-1197` here) — but that block is also the fallback that produces the installed `libbpf.so` (`src/init/inst-functions.sh:1010-1015`). Removing it while keeping the `dlopen("libbpf.so")` dependency is a latent from-scratch-build break.

On the dlopen path itself: `rt_engine.c:94-98` tries `libbpf.so.1` then `libbpf.so`; the agent installs only `libbpf.so`, so the fallback branch is the operative one — behaviourally equivalent to today's `so_get_module_handle("bpf")`. The provider bypasses Wazuh's `sym_load` wrapper and calls raw `dlopen`, which is an inconsistency worth noting but not a blocker; its own header comment already flags resolving Wazuh's bundled path as "a real follow-up."

### Decision

**Do not import `ebpf_provider/CMakeLists.txt` as written.** Rewrite it to:

1. keep the Linux-only early `return()` (`:12-15`) — that part is right;
2. drop `REQUIRED` from both `find_program` calls;
3. gate the object build on `EXISTS ${prebuilt}` first, exactly the pattern `src/external/CMakeLists.txt:1185` already uses for `modern.bpf.o`, then on toolchain availability, and skip it otherwise with a `message(STATUS …)`;
4. prefer the **portable per-arch** `vmlinux.h` the existing pipeline already vendors (`external/libbpf-bootstrap/vmlinux.h/include/${ARCH}/vmlinux.h`) over dumping the build host's BTF;
5. keep `rt_engine` (pure C, `dl` only, PIC on) building **unconditionally** — it has no toolchain dependency and compiles fine in WSL;
6. leave `src/external/CMakeLists.txt` and `inst-functions.sh` alone in phase A1.

Ruled out: importing as-is and "fixing CI later" — it fails `cmake` configure, i.e. it breaks the build for everyone including WSL, which is the one environment where the rest of this branch is developed.

Insertion point: `src/CMakeLists.txt`, in the `if(IS_AGENT)` block after `add_subdirectory(shared_modules/sync_protocol)` (line 257) and before `add_subdirectory(syscheckd)` (line 258) — where `0ce0c2fbc0` put it, and correct, since `fimebpf` will link `rt_engine`.

---

# Part A — The import

## 11.7 Phased plan

Ordering principle: **the provider lands and builds before anything consumes it, and the FIM baseline driver is never in the blast radius.**

### A0 — Prep (no code)

1. Ratify §11.1's version decision.
2. Read `spike-37396/adr/ADR-001..003` on `enhancement/37396-ebpf-provider-spike` — the provider's comments treat them as normative and they explain the "no shared provider" and versioning rules the plan below relies on.
3. Optionally do [08 item 31](08-roadmap.md#p3--maintainability)'s first half now: move `container_baseline_fim.{cpp,h}` and `container_baseline_fim_bridge.{c,h}` out of `src/syscheckd/src/ebpf/`. Not required, but it makes "the eBPF directory contains only eBPF things" true before new eBPF code arrives, and removes a genuinely confusing adjacency.

### A1 — The provider lands; nothing consumes it *(smallest first useful step)*

- Add the seven files verbatim from `9113442eb4:src/shared_modules/ebpf_provider/` (`CMakeLists.txt`, `Makefile`, `bpf/rt_file.bpf.c`, `include/rt_engine.h`, `include/rt_event_contract.h`, `src/rt_engine.c`, `test/rt_engine_harness.c`). **Zero conflict** — the directory does not exist here.
- Replace `CMakeLists.txt` per §11.6.
- Add the one line to `src/CMakeLists.txt:258`.
- **Do not touch** `src/syscheckd/src/ebpf/*`, `src/external/CMakeLists.txt`, `src/init/inst-functions.sh`, or `modern.bpf.c`.

**Method: port by hand; do not cherry-pick.** The three commits are entangled with the whodata cutover (−508 lines of `ebpf_whodata.cpp`, `bpf_helpers.h` cut from 188 lines, 4 deleted test files), the externals removal and `container_live_fim.cpp`. A cherry-pick of `0ce0c2fbc0` alone touches 22 files. Taking the provider directory as a unit and writing the wiring fresh keeps A1 to **8 new files and 1 changed line**.

Verification: WSL `make build TARGET=agent` still configures and links (`rt_engine.c` is plain C; the object step no-ops). VM: full `make build`, plus `make -C src/shared_modules/ebpf_provider && sudo ./rt_engine_harness A all` to prove real load/attach/poll.

Result: the provider exists and is buildable. No behaviour change anywhere. FIM still uses `modern.bpf.o`.

### A2 — Close the provider gaps item 21 depends on *(before any consumer)*

Implement §11.9 items 1–7 inside `src/shared_modules/ebpf_provider/` only. Item 1 (in-kernel filtering) and item 2 (per-cgroup drops) are the two the algorithm cannot be sound-at-scale without; item 3 (log callback) is what makes field diagnosis possible; item 4 (link teardown) is a correctness bug. All are additive to the provider — nothing else in the tree changes, so A2 can be reviewed and VM-validated on its own.

### A3 — A *second* consumer, not a cutover

Add a container-events consumer inside `fimebpf` that opens its **own** `rt_handle_t`, with its own filter and its own drain thread. **Deliberately leave `ebpf_whodata.cpp`'s existing libbpf path untouched.**

Why: it keeps host whodata and its seven test files (734 lines) out of the blast radius entirely, so a regression in item 21 cannot break host FIM, and item 21 can be validated on its own. ADR-001 explicitly sanctions independent per-consumer loads.

Cost, stated honestly: a second `bpf_object` load, a second 8 MiB ring buffer, and duplicate kprobes on the same hooks — so the kernel-side cost of the file hooks roughly doubles while both paths coexist. **Measure it on the VM** (`bpftool prog list` run_cnt/run_time_ns before and after). If unacceptable, that is the argument for A4; if acceptable, A4 stays optional.

Port from `415e7a2204` (adapting, not copying wholesale): the `rt_engine_api_t` mock seam (`ebpf_whodata.hpp:27-34`), `matches_container_prefix()`, the `containerEventQueue` + dedicated worker split, and `container_live_fim.cpp`'s cgroup→container→`/proc/<pid>/root` resolution and `lstat`-decides-delete primitive — **with the corrections in §11.8.5**, and with the per-event IPC replaced by §11.4's map. Drop the temporary `mdebug2` instrumentation the spike left in, or gate it behind `syscheck.debug`.

Also fix, while porting: the spike's own `extern "C"` include-ordering trap (`time_op.h` must be wrapped *first*, before `syscheck.h` pulls it in unwrapped, or `get_iso8601_utc_time` gets C++ linkage and the link fails — documented in the test-plan doc, and it cost a build cycle on the VM).

### A4 — Optional, later: cut host whodata over and de-duplicate

Port `0ce0c2fbc0`'s `ebpf_whodata.cpp` changes, delete `modern.bpf.c`/`modern-arm.bpf.c`, repoint `inst-functions.sh:648-660` to `build/lib/rt_file.bpf.o`, and decide the `libbpf_external` question (§11.6 — keep the block for `libbpf.so`, stop using it for the object). This deletes four test files — `close_libbpf_test.cpp` (67), `init_bpf_obj_test.cpp` (97), `init_libbpf_test.cpp` (90), `init_ring_buffer_test.cpp` (77) = 331 lines — whose subject (libbpf plumbing) no longer exists in `fimebpf`. Their coverage must be **replaced** in the provider's own suite (§11.10), not simply removed.

This is where the real conflict surface is, and it buys de-duplication, not function. Do it only after A3 is validated, and only if A3's measured duplication justifies it.

### Does duplication remain?

Yes, deliberately, from A3 until A4: two BPF loads, two ring buffers, two drain threads. That is the price of not putting host FIM whodata at risk while item 21 stabilises, and ADR-001 already accepts it as the module's model. Say so in the commit message rather than leaving a reviewer to discover it.

---

# Part B — The algorithm

## 11.8 Subscribe-first, scan, reconcile-by-re-read — against the real contract

### 11.8.1 Ordering

Three clocks, and they must fire in this order:

```
main.c:
    fim_initialize();
    cfim_events_start();          /* NEW: rt_open + attach + drain thread;
                                     every matching event goes to per-container staging */
    fim_run_container_baseline(); /* main.c:486 — unchanged call site */
    realtime_start();             /* main.c:491 */
```

Today the handle is opened inside the `ebpf_whodata` thread created at `run_check.c:929`, from `start_daemon()` — long after the walk. That must move.

**Explicit decision on the healthcheck.** The existing eBPF startup runs a four-action healthcheck (create / modify content / modify metadata / delete a probe file) with a 10 s timeout each. Run it **before** the walk, accepting up to ~40 s of worst-case added startup latency, rather than in parallel. Rationale: if the healthcheck is still running (or fails) while the walk proceeds, the walk was unmonitored and *every* container must be re-baselined — which costs far more than 40 s. Ruled out: running them concurrently for startup speed.

### 11.8.2 Sequence numbers — the consumer mints them

[06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff) says "Record S0 = current event sequence." **No sequence exists.** The candidates are `timestamp_ns` (`bpf_ktime_get_boot_ns`, `rt_event_contract.h:76`) and the drain order of `rt_poll`.

Use a **consumer-assigned monotonic counter stamped in the drain callback.** It is the only value totally ordered with respect to the consumer's own state machine; the kernel timestamp is not (libbpf's ring buffer preserves per-CPU submit order, not a global order, and a boot-time clock read on one CPU can precede an earlier logical event on another). Keep `timestamp_ns` for alerting and diagnostics.

`S0` = the counter's value when container C enters Staging. `S1` = its value when C's walk completes. Neither is compared against event fields — they exist only to bound the staging window and to make the invariants below testable.

### 11.8.3 Per-container state machine

```
                     event for unknown cgroup, or item-20 create trigger
                                    │
 Unknown ───────────────────────────▼──────────► Staging ──► Walking ──► Reconciling ──► Live
                                                    ▲                                    │
                                                    │      overflow / drop / re-open     │
                                                    └──────────── Suspect ◄──────────────┘
    (absent from container_instances' list) ─────────────────────► Gone
```

| State | Subscription | Events for C | Walk | DB |
| --- | --- | --- | --- | --- |
| **Unknown** | global, active | first event creates the entry and schedules a walk | — | — |
| **Staging** | active | appended to C's bounded staging set; `S0` recorded | queued | untouched |
| **Walking** | active | keep staging — **never apply** | running, streaming into C's scoped txn | one open scoped txn |
| **Reconciling** | active | keep staging (new arrivals join the next drain) | committed; `S1` recorded | txn finished per `partial` |
| **Live** | active | applied immediately by re-read | — | single-row upserts |
| **Suspect** | active | staged | re-walk queued | untouched until the walk |
| **Gone** | n/a | discarded | — | swept |

Notes that fall out of the real contract:

- **Unknown → Staging on first event** makes the spike's "Option C catch-up walk" the *normal* entry path rather than a repair (`825214fd61:spike-37533/startup-race-solutions-and-edge-cases.md`). It is the only mechanism that covers a container which starts after the agent and is missed by every list poll.
- **A container that starts mid-baseline** enters Staging immediately (via its first event or the item-20 trigger) and its walk is queued behind the in-flight one. It never shares a transaction with another container — the scoped-txn key is `container_id`.
- **A container that exits mid-baseline**: `RootfsStillAddressable()` (item 24, commit `d8054738d6`) already reports the scan as incomplete rather than emitting a silent partial row set, and `SelectAddressablePid()` (`d8e4cd5704`) already treats all-PIDs-gone as *unscanned*, not *empty*. Keep both. On exit: `partial = true` → no delete detection → **rows left intact**, which is exactly [06 §6.8](06-proposed-architecture.md#68-deletion-semantics-stated-once)'s row 3. Its staged events are discarded (nothing to re-read through) and C is marked Suspect so a restart re-walks.
- **Bounding the staging set**: key it by **path**, keeping one entry per path (last-writer-wins) plus a sticky "some event for this path was UNLINK/RENAME" bit. Since the payload is never trusted, one entry per path carries all the information the reconcile needs, and the buffer is bounded by the number of *distinct changed paths*, not by event count — which is what makes a write storm on a handful of files survivable. `BoundedQueue`'s `push()`-returns-false already gives the overflow signal; a path-keyed map is the better structure here and `BoundedQueue` should be retained for the raw drain hand-off only.

### 11.8.4 Reconcile-by-re-read: validated, and now forced

[06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff) proposed re-reading the affected path rather than trusting the event payload. **Validate it — and note it is no longer a preference but the only possible design**, for a reason 06 could not have known:

`struct rt_file_event` contains **nothing you could build a FIM row from.** No mode, no uid/gid of the file, no size, no mtime, no hash. `inode` and `dev` are documented as diagnostic-only. `event_type` is not even carried into the consumer's staged struct today. And `FILE_OPEN` fires on write *intent*, so the event cannot tell you whether a modification has happened yet.

Therefore the only sound rule is: **an event names a (container, path); a `stat` + hash of the resolved host path decides added / modified / deleted.** That is precisely what `415e7a2204:container_live_fim.cpp:746-752` already does (`lstat` fails → delete; `!S_ISREG` → skip; otherwise upsert).

Two revisions to the sketch that the real contract forces:

**(i) Drop the "P not visited by the scan → apply as a normal change" branch.** Applying an event for a not-yet-walked path *during* the Walking state means a single-row upsert racing the same container's open scoped transaction. That is not theoretical — it is the exact bug hit and fixed on the VM: a concurrent catch-up walk and a triggering-event upsert on the same `container_id` persisted 1–2 rows out of 504 and **silently lost the rest** (`startup-race-solutions-and-edge-cases.md`, "First attempt"). The fix there was to serialise onto one thread; the fix here is to serialise onto one *state*. So: **every staged event is reconciled by re-read after the commit, unconditionally.** One diff per affected path either way, and the branch that distinguished them disappears — it only existed because the sketch assumed the payload was applicable.

**(ii) `Live` requires `partial == false`.** The sketch's "no event can predate S0" argument is correct but incomplete: it relies on the walk reading the file after `S0`, which holds only if the walk *reaches* that path. Under a row cap, a deadline, an absent path or an unreadable namespace, some paths are never read — so a pre-`S0` change to such a path is in neither the baseline nor the staging set. This is not a new defect; it is the existing `partial` contract (`ContainerStatus::partial`, `container_baseline_scanner.hpp:52-59`). But it means **a partial baseline may never transition to Live.** It stays in Staging, with the un-walked remainder covered only by the periodic rescan, until a complete walk succeeds.

### 11.8.5 Composing with `ContainerStatus` — the false-deletion invariant

**Invariant: a deletion may be emitted only from a completed read of a live, verified rootfs. Never from the absence of an event, and never from a single failed `lstat`.**

Five rules implement it:

1. **A failed re-read produces a delete only if both (a) the container has a live *addressable* PID at that moment (`SelectAddressablePid()` succeeded) and (b) a row for `(container_id, path)` actually exists.** Today `container_live_fim.cpp:746-749` checks **neither**: `lstat` failure goes straight to `delete_container_file_row()`, which calls `fim_persist_baseline_row(id, OPERATION_DELETE, …)` and `fim_db_container_file_delete()` unconditionally (`:343-367`). A create-then-delete inside one poll window therefore emits a DELETE document for a row that never existed. Fix with a per-path existence check — the `container_has_existing_rows()` `LIMIT 1` pattern (`:370-379`) applied at path granularity.
2. **PID death or PID reuse between selection and `lstat` means "unknown", not "deleted".** Requeue once; on second failure drop the event and mark C **Suspect**. Re-validate identity by comparing `ExtractContainerIdFromCgroupPath(read("/proc/<pid>/cgroup"))` against the expected `container_id` — the TOCTOU the startup-race doc names explicitly.
3. **`partial == true` continues to suppress delete detection** (`container_baseline_fim.cpp:231-239`; syscollector's equivalent per-table suppression from item 7) — unchanged, and now additionally blocks the Live transition.
4. **Drops never produce deletes.** A drop produces Suspect + re-walk, and the re-walk is what may legitimately delete.
5. **Stopped-but-known containers keep their rows** ([06 §6.8](06-proposed-architecture.md#68-deletion-semantics-stated-once) row 3; `sweepStale` only ages out ids absent from `cbaseline_list_containers()`). Events for a container with no live PID cannot be reconciled at all → discard and mark Suspect.

Why re-baselining is safe as the universal recovery: rows go through a **scoped** `DBSync` transaction that computes INSERTED/MODIFIED/DELETED against what is already stored, so a re-walk that finds nothing changed emits nothing. That single property is what lets every Suspect edge collapse to "re-walk C" — as [06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff) argued, and it holds.

One subtlety on stateless alerts: the baseline path persists rows but does **not** emit stateless events, while the live path does (`send_container_stateless_event()`, `container_live_fim.cpp:170+`, reusing `file.c`'s `fim_attributes_json`/`fim_calculate_dbsync_difference`). Syscollector's per-container first-sync quiet guard (`m_knownContainerIds` + `notifyOverride`, `syscollectorImp.cpp:2185-2201`) is the model: **a re-walk of a Suspect container must be quiet for rows it re-confirms and loud only for genuine diffs** — otherwise an overflow-triggered re-baseline becomes an alert storm, which is the failure mode the whole `partial`/first-sync machinery exists to prevent.

### 11.8.6 Fallback when eBPF is unavailable

`rt_open` returns `NULL` on old kernels, missing BTF/CO-RE, absent `libbpf`, a missing `.bpf.o`, or insufficient capability. On cgroup-v1 hosts it *succeeds* but attribution is impossible (§11.4). So:

**Availability = `rt_open() != NULL` **and** cgroup v2 **and** a non-empty `cgroup_id → container_id` map.** All three, evaluated per host; the middle one currently has to be probed by the consumer because `RT_F_CGROUP_V1` is never set.

The fallback is **not** "do nothing" — it is exactly today's behaviour: syscollector's per-interval `scanContainerBaseline()` (`syscollectorImp.cpp:2426`) plus FIM's startup walk and item 20's create trigger. So the design is: **the event tier is an accelerator layered on a rescan cadence that always exists.**

Concretely, two intervals and one rule:

- `container_rescan_interval` — always active. Its value must **not** be lengthened on the assumption that events exist.
- `container_reconcile_interval` — a much longer safety net (06's 24 h), used *instead* of the short one only for containers that are actually `Live`.

Selected per container, not per host: a `partial` container, a Suspect container, a cgroup-v1 host and a kubelet-written mount path all keep the short cadence even when the provider loaded fine. And whichever path is taken must be **logged once at startup, at INFO** — the VM run's step-3 finding is precisely that an inactive eBPF path is currently undetectable from the log.

### 11.8.7 Interaction with items 20 and 23

**Item 20 is a hard prerequisite for item 21, not a sibling.** Two dependencies:

1. The `cgroup_id → container_id` map (§11.4) comes only from the `list`/`watch` reply. Without item 20's refresh trigger, the map is built once at startup and every container created later is a permanent cold miss — falling back to per-event IPC, i.e. the thing item 21 exists to avoid.
2. Staging must begin *before* the walk for a newly created container. Without a create trigger, the only Staging entry point is "an event arrived for an unknown container" — sound (and it covers the startup race), but it can never baseline a container that simply never writes.

**Item 23's trigger table needs one row rewritten.** "eBPF ring-buffer drop for C → re-baseline C" is not implementable: drops are a single global counter with no key (§11.2). Replace with:

> **Drop observed** (any event with `RT_F_DROPS_BEFORE`) → mark **every** container not currently `Live` as Suspect, and every `Live` container Suspect if the global drop counter has advanced since that container's last reconcile.

That is deliberately pessimistic and it will cause unnecessary re-walks — which is the honest cost of a global counter, and the concrete argument for §11.9 item 2. Every other row of 06's trigger table survives unchanged, including the reload-widening row, which should keep reusing the existing first-sync guard.

**Item 14 (move the work off critical threads) becomes mandatory.** Opening the handle before `main.c:486` and draining on a dedicated thread means the walk can no longer share `main()` with the drain if the two are to interleave. [09](09-implementation-status.md#not-done--deliberately-deferred) already records that item 14 "interacts with item 21's ordering" — it does, and item 21 forces it.

**Item 15 (bounded concurrency) stays deprioritised**, and item 21 does not change that: the reconcile work is a handful of re-reads per container, dominated by hashing, which is already `check_max_fps`-throttled.

---

## 11.9 What must be added to `ebpf_provider`

Ranked by whether item 21 works without it.

| # | Addition | Where | Why item 21 needs it |
| --- | --- | --- | --- |
| **1** | **In-kernel filtering.** A `BPF_MAP_TYPE_HASH` allowlist keyed on `cgroup_id` (plus a "monitor everything" mode for host whodata), checked in `submit_event` before `bpf_ringbuf_reserve`. | `bpf/rt_file.bpf.c:243-250`; new field in `rt_filter` + map-update entry points in `rt_engine.c` | **The single most important item.** Without it: whole-host firehose × 12,416 B into an 8 MiB buffer (~675 events) → routine drops → routine Suspect → the algorithm degrades to permanent re-baselining. Complementary win: reserve only the actual path length instead of 3×4096 fixed bytes. |
| **2** | **Per-cgroup drop accounting** (per-cgroup counters, or a synthetic `RT_EV_DROP` record carrying `cgroup_id`). Also make the read-reset atomic. | `drops_map` (`:80-86`), `take_drop_counter` (`:100-111`) | Makes item 23's per-container re-baseline trigger implementable instead of escalate-to-all (§11.8.7). |
| **3** | **A logging seam** — `void (*log)(int level, const char* msg)` on `rt_filter`. | `rt_engine.h:29-47`; the eight `fprintf(stderr)` sites in `rt_engine.c` | Today an eBPF load failure never reaches `ossec.log`. "eBPF unavailable, using periodic rescan" must be diagnosable in the field; the VM run proves it currently is not. |
| **4** | **Destroy the `bpf_link`s in `rt_close`.** Store them from `bpf_program__attach`. | `rt_engine.c:276-283`, `:319-335` | Correctness bug: probes stay attached after close, the freed ring buffer keeps being written (drop counter climbing against no consumer), and a re-open double-attaches → duplicate events. |
| **5** | **Actually set `RT_F_CGROUP_V1`.** | declared `rt_event_contract.h:57`, never set (`rt_file.bpf.c:256,274`) | Without it the consumer must probe cgroup version out of band, and a v1 host silently mis-attributes every event to one bogus cgroup. |
| **6** | **ABI guard** — `rt_open` refuses on `abi_major` mismatch, or expose `rt_abi_check()`. | `rt_engine.h`, `rt_engine.c:225` | No consumer checks `abi_major` today. A stale `.bpf.o` against a newer header would mis-parse a 12 KB struct read by raw reinterpretation on both sides. |
| **7** | **Occupancy metric** — resolve `ring__avail_data_size`. | `libbpf_api` table, `rt_engine.c:53-69` | Lets the consumer start staging / throttle *before* overflow rather than reacting to `RT_F_DROPS_BEFORE` after the fact. |
| **8** | **Kernel-portable rename** — select the `renamedata` shadow at runtime (`bpf_core_field_exists`, or two `___local` variants keyed on `LINUX_KERNEL_VERSION`), and add a **rename** action to the healthcheck. | `rt_file.bpf.c:498-559` | Otherwise rename events silently vanish on one kernel family — the same silent-detection-gap class the file's own comment documents for `modern.bpf.c`, just inverted. A healthcheck action makes it loud. |
| **9** | **A unit-test seam.** `CMakeLists.txt:75-79` says there are none. | new `test/` gtest + a fake libbpf | The dispatch table is already function-pointer based, so a fake libbpf is cheap; without it every `rt_open` failure branch needs a kernel. |

Items 1–4 are prerequisites for A3. Items 5–9 can land in parallel with it.

---

## 11.10 Test plan

### WSL-runnable

- **New `src/shared_modules/ebpf_provider/test/` gtest suite** (item 9 above), against a fake libbpf:
  - `rt_open` returns `NULL` for `type_mask == 0` and for a mask with no `RT_FILE_*` bits (`rt_engine.c:227-231`).
  - `rt_open` returns `NULL` when the fake fails at each of `open_file`, `load`, `attach`, `find_map_fd_by_name`, `rb_new` — five cases, one per branch (`:247-302`), each asserting no leak.
  - `rt_close(nullptr)` is a no-op; `rt_poll(nullptr, …)` returns `-1`.
  - **ABI pin**: `sizeof(struct rt_file_event) == 12416` plus `offsetof` assertions on `cgroup_id`, `mnt_ns`, `dropped`, `filename`, `cwd`. The struct is read by raw memory reinterpretation on both sides — this is the test that stops a silent 12 KB mis-parse.
  - `type_bit_for_section()` table (`:160-179`): each section string → the right bit; and `select_programs()` (`:181-212`) keeps `lsm/file_open` and drops `kprobe/vfs_open` when `prefer_lsm`, and vice versa.
  - After item 4: `rt_close` destroys exactly as many links as `rt_open` created.
- **New container-event consumer tests** against the `rt_engine_api_t` fake (the seam already exists at `415e7a2204:ebpf_whodata.hpp:27-34`):
  - `Staging → Walking → Reconciling → Live` transitions, with events injected in each state.
  - Staged path-dedup: N events on one path produce exactly one re-read and one diff.
  - Staging overflow → Suspect → re-walk.
  - An event with `RT_F_DROPS_BEFORE` → the §11.8.7 escalation, and **no** DELETE for any still-existing path.
  - **Delete suppressed when no row exists** (the create-then-delete case) and **when no live PID exists**.
  - PID-reuse re-validation rejects a recycled PID whose cgroup resolves to a different container.
  - `partial == true` never reaches `Live`.
  - An event for an unknown `cgroup_id` creates a Staging entry and schedules a walk exactly once, even under a burst.
- **Extend `container_baseline_impl/tests/`** (the 15 orchestrator tests from `6a08712dbe`, plus the row-contiguity self-checks) with a `cgroup_id → container_id` map built from a fake `list` reply, including rows where `cgroupId == 0` (the v1 case) and duplicate `cgroupId`s.
- Constraint: per [09 §Environment notes](09-implementation-status.md#environment-notes-found-while-verifying), `TEST=yes` cannot configure in this WSL environment (CMake 4.4.2 vs googletest's `cmake_minimum_required(2.8.12)`), so these must be run against a locally compiled gtest as before, or on the VM.

### VM-only (`wazuh_manager`)

Flagged because none of these can be done in WSL — the BPF object cannot be built or loaded here.

1. **Build**: `make deps TARGET=agent` + `make build -j$(nproc) TARGET=agent` with the new subdirectory. The only place the object compile and the `librt_engine` link are actually exercised.
2. **Provider in isolation**: `make -C src/shared_modules/ebpf_provider && sudo ./rt_engine_harness A all`. Then two concurrent instances with disjoint filters (`A open,unlink` / `B attr,rename`) to test ADR-001's independence claim — and, after item 1, that A's allowlist does not leak B's events.
3. **Config prerequisites** (both absent from the shipped `ossec.conf`, per test-plan step 3): `<directories tags="container" whodata="yes" recursion_level="5">/etc</directories>` and `<syscheck><whodata><provider>ebpf</provider></whodata>`. Without the second, the entire eBPF path is never attempted and the test silently measures the Audit provider.
4. **Ordering proof**: start the agent while a container writes continuously to `/etc`. Assert every write is either present in the baseline row set **or** produced exactly one diff, and that **no path produces two events**. This is the test for item 21's headline claim.
5. **Loss proof**: `docker exec … sh -c 'for i in $(seq 20000); do echo x > /etc/f$i; done'`. Assert (a) `RT_F_DROPS_BEFORE` is observed, (b) affected containers reach Suspect and re-walk, (c) **no DELETE is emitted for any file that still exists**. This is the test that decides whether §11.9 item 1 is optional or mandatory — run it before and after that change and record both numbers.
6. **False-delete proof**: create-then-immediately-delete inside a container; assert no DELETE document for a path that never had a row.
7. **cgroup v1**: on an AL2 or RHEL8 guest (per ADR-002's matrix), assert the agent logs "eBPF container events unavailable (cgroup v1)" at INFO and falls back to rescan — rather than attributing every event on the node to one bogus cgroup.
8. **configMap gap, pinned deliberately**: update a live ConfigMap on the kind cluster; assert it is **not** captured live and **is** captured by the next rescan. Better to pin the documented gap than to leave it as an untested claim.
9. **Rename**: exercise on both kernel families if a second guest is available; otherwise record as unverified (see §11.11).
10. **Regression**: `ctest --output-on-failure -R fimEbpfWhodataTest` green after A1 (which must not touch it at all) and after A3. Plus the container_baseline module's 161 tests (160 pass / 1 skipped per [09](09-implementation-status.md)).
11. `rebaseline.sh --follow --debug` to force the one-shot walk to re-run without a full restart, for iterating on 4–6.

---

## 11.11 Open questions and what I could not verify

1. **Is the kernel-reported path container-relative in *all* mount configurations?** *(Correction, see
   [12 §12.8](12-blocking-decisions.md#128-what-the-five-spike-documents-settled): this question
   overstated its evidence. The volume-type matrix document states of itself that it was **not**
   validated against a running cluster — it is code inspection plus general Kubernetes/Docker
   semantics. The real kind-cluster run is in a different document and covered baseline and live-path
   behaviour, not the matrix. This question is **fully open**, including the narrower concern below.)*
   ~~Confirmed for the overlay rootfs and for the volume types in the matrix by the VM run.~~ The kprobe walker (`rt_file.bpf.c:116-188`) terminates at `mnt == mnt_parent`, which I reason is the container's mount-namespace root — but I did **not** verify it for a container sharing a mount subtree with the host under peer/slave propagation, nor for a bind mount whose source lies above the container root. Needs a VM check; if it can yield a host-namespace path for some mounts, the `/proc/<pid>/root` prefix would produce a wrong path with no error.
2. **Does `bpf_get_current_cgroup_id()` equal the cgroup directory inode that `InodeReader::inodeOf` returns, on every supported kernel?** **Answered for kernel 7.0 / cgroup v2 and now pinned by a test** (`ebpf_provider/test/rt_engine_drops_test.c`, commit `c590808019`): the test creates two cgroups, provokes drops from a process in each, and asserts the drained keys equal `stat()` of the directories it created — observed 28126 and 28206 for both. Still unverified on cgroup v1 (where the id is a constant anyway) and on older kernels. ~~The whole attribution scheme is this join, and I could not find it asserted anywhere in tree~~ — `container_instances` assumes it (`i_cgroup_resolver.hpp` `CgroupEntry::inode`) and the VM run proves it holds there. Worth a one-line explicit test.
3. **The exact kernel release boundary for the `struct renamedata` layout change.** I read both shadow structs; the provider's comment cites only "kernel 7.0.0". I deliberately did not guess a version — hence §11.9 item 8's recommendation to derive it at runtime rather than encode a boundary.
4. **Is the drop counter ever non-zero on a realistic node?** ~~No measurement exists anywhere.~~
   **Measured — see [12 §12.9](12-blocking-decisions.md#129-d4-answered--the-loss-proof-measured).**
   Yes, but it takes tens of thousands of events per second: a single-threaded 8,400 ev/s burst of
   20,000 file creates lost nothing, while ≈198,000 events from 10 parallel producers lost 203
   (≈0.10%). §11.9 item 1 therefore **improves** A3 rather than blocking it. The measurement also
   **inverts item 1 and item 2's priority**: those 203 lost events surfaced as just *three*
   flag-bearing events from one unkeyed global counter, so §11.8.7's escalation would re-baseline
   every container on the node three times for a 0.1% loss. Item 2 is the one the algorithm cannot
   be correct without. It also settles a contract detail: `dropped` is a **read-and-reset delta**
   (the three events carried 188, 11 and 4, summing to the observed loss), not a running total.
5. **Does `dlopen("libbpf.so")` resolve against `${INSTALLDIR}/lib` in the installed agent?** Only `libbpf.so` is installed (`inst-functions.sh:1010-1015`), not `libbpf.so.1`, so the provider's fallback branch is the operative one. The existing code uses the same relative name and works, so it should — but I did not read the rpath/link flags to confirm.
6. **Does removing `libbpf_external` break a from-scratch build with no prebuilt deps tarball?** That block is also the fallback producing the installed `libbpf.so`. §11.6 recommends keeping it; not verified by building.
7. **Two spike observations I could not resolve from code.** (a) The **duplicate `handle_event` routing line**: every real test write produced *two* identical container-candidate routing lines but only one set of downstream processing lines. Two genuine kernel events per logical write, one event delivered twice, or a logging artefact — the trace didn't log `event_type`, so the three cannot be distinguished. This **directly affects staged-path dedup accounting and any drop arithmetic**, so add `ev->event_type` to the trace before trusting event counts. (b) Whether `container_instances` will expose an `mnt_ns` index or a per-connector readiness signal (`startup-race-solutions-and-edge-cases.md` Option A) — both would materially simplify §11.4 and the startup race, and both are that module's decision, not this one's.
8. **`spike/37533-37534-fim-syscollector-ebpf-integration` carries a separate "reconcile".**
   *(Factual half resolved — see [12 §12.1](12-blocking-decisions.md#121-the-finding-that-reorders-the-roadmap).
   That branch is not a parallel effort: it is the source this branch was cut from, at
   `66301af90d`, and 14 commits of its feature work — `5a9021e285` included — were never
   integrated. `5a9021e285` **replaces** the inventory state model rather than complementing it.
   The remaining question is which model wins, registered as
   [12 D1](12-blocking-decisions.md#blocking-now--every-further-design-step-depends-on-these).)* Commit `5a9021e285` "feat: added reconcile poc with new states schema" adds `container_baseline_impl/include/reconcile/*` — an inventory prior-state store with `container_inventory_reconciler`, `row_diff`, `sqlite_prior_state_store` and ~420 lines of tests, refactoring 260 lines out of `container_baseline_scanner.cpp` and 159 out of `syscollectorImp.cpp`. That is **not** the eBPF handoff, despite sharing the word "reconcile". Whether it supersedes, complements or conflicts with item 21's reconcile step is a coordination question I could not settle from the commits alone, and it should be settled before A3 — it touches the same scanner and the same syscollector call path.
9. **`ContainerHandle`'s `O_PATH` fd pinning** ([08 item 24](08-roadmap.md#p2--architecture-make-it-a-baseline), still open per [09](09-implementation-status.md)) would let a re-read survive a mid-flight PID exit. [09](09-implementation-status.md#not-done--deliberately-deferred) questions its value for the *walk*; for the **live re-read** the calculus differs — a pinned `rootfs_fd` would remove the PID-reuse TOCTOU (§11.8.5 rule 2) entirely, because `openat`-relative traversal cannot be redirected by PID recycling. Worth re-opening on those grounds specifically.

### Where the provider's real contract contradicts the existing design docs

> **Partly superseded.** This table was written against the provider as imported. Two of its rows
> have since been fixed *in the provider* rather than worked around in the consumer, and are marked
> below. [06 §6.10](06-proposed-architecture.md#610-corrections--the-sketch-versus-the-implemented-contract)
> carries the current, consolidated list, including two defects (C21, C22) found only by running the
> engine against real containers.

| Doc | Claim | Reality |
| --- | --- | --- |
| [06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff) | "SUBSCRIBE — attach the eBPF filter **for C**" | *When written:* no per-container filter existed; `rt_filter` was `{type_mask, bpf_obj_path}` and subscription was global and unfiltered. **Since fixed** (`d560d22b37`): the BPF program now filters by cgroup allowlist (`rt_allow_cgroup`, `RT_CGROUP_MODE_ALLOWLIST`), before a 12,416-byte ring reservation is attempted. Still not a per-container *attach* — one handle, one allowlist — and the consumer runs in mode ALL until item 20's create trigger exists, since an unlisted cgroup is invisible rather than unattributed. |
| [06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff) trigger table | "#37203-2 signals a ring-buffer drop **for C** → re-baseline C" | *When written:* drops were one global, unkeyed counter, not attributable to a container. **Since fixed** (`c590808019`, [D14](12-blocking-decisions.md)): `rt_drain_drops()` reports loss per cgroup. The measurement that motivated it — 203 dropped events surfacing as three flag-bearing events — is why acting on the global counter would have re-baselined every container three times for one container's 0.1% loss. |
| [06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff) | "Record S0 = current event **sequence**" | No sequence is provided. Only `timestamp_ns`, which is not globally ordered. The consumer must mint its own. |
| [06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff) | "P not visited by the scan → apply as a normal change" | Unsound during the walk: a single-row upsert racing the same container's open scoped transaction silently lost 502 of 504 rows on the VM. Every staged event must be reconciled after the commit. |
| [06 §6.6](06-proposed-architecture.md#66-tiering-the-data-classes-s4) | Event-maintained = "FIM files, processes, ports" | The provider has **no process and no socket event class** (`rt_event_contract.h:20-22`). Only files hand off; processes and ports move to Sampled. |
| [07 §7.5](07-options-matrix.md#75-ebpf-assisted-baseline-m6-assessed-and-set-aside) | "Whether #37203-2 exposes an enumerate-on-attach hook is an open question" | **Answered: no**, and structurally so — the engine has no notion of a container or a cgroup at all. M6 correctly stays out of v1, and user-space `/proc` walking (M3) is required. |
| [09](09-implementation-status.md#not-done--deliberately-deferred) | Item 21 "blocked on #37203-2's event contract and overflow signal" | Both now exist. Item 21 is **unblocked**, but with three gaps: no container attribution in the event (solvable consumer-side, §11.4), no per-container loss attribution (needs §11.9 item 2), and no in-kernel filtering (needs §11.9 item 1). |
