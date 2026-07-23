# Current-State Audit — eBPF inside FIM (whodata)

Spike #37396 / parent #37203. All paths relative to repo root. Grounded in code read on branch `fix/6761-appx-store-python-name-resolution`.

## 1. Where the code lives

```
src/syscheckd/src/ebpf/
├── CMakeLists.txt                     # builds libfimebpf.so, links into wazuh-syscheckd
├── include/
│   ├── ebpf_whodata.h                 # C ABI exposed to FIM (extern "C")
│   ├── ebpf_whodata.hpp               # fimebpf singleton (callback wiring) + globals
│   ├── bpf_helpers.h                  # file_event / dynamic_file_event structs, libbpf fn-ptr table
│   ├── wrapper_bpf.h                  # libbpf skeleton struct decls + fn-ptr externs
│   ├── bounded_queue.hpp              # fim::BoundedQueue<T> (the only backpressure primitive)
│   └── dynamic_library_wrapper.h      # dlopen/dlsym seam (test injection)
└── src/
    ├── ebpf_whodata.cpp               # THE ENGINE: load/attach/poll/fanout (772 lines)
    ├── modern.bpf.c                   # BPF programs, x86 (984 lines)
    └── modern-arm.bpf.c               # BPF programs, arm (465 lines)
```

BPF object build is **out of tree** of the agent build: `compile-ebpf/libbpf-bootstrap/` clones `bpftool` + `vmlinux.h`, compiles `modern.bpf.c` with clang, runs bpftool gen skeleton, and `sed`-rewrites `#include <bpf/libbpf.h>` → `"wrapper_bpf.h"` in the generated `modern.skel.h`. The compiled artifact ships as `lib/modern.bpf.o` and is loaded at runtime. libbpf itself is vendored under `src/external/libbpf-bootstrap` and **loaded via `dlopen`** (see `init_libbpf`), not linked directly.

**No new external dependency is needed for the extraction** — libbpf + CO-RE + BTF + `BPF_MAP_TYPE_RINGBUF` are already the in-tree mechanism. This satisfies the hard constraint. (Confirmed: `bpf_helpers.h` resolves every libbpf symbol by name through `dlsym`.)

## 2. How programs are built / attached (runtime path)

1. `check_ebpf_availability()` (`src/syscheckd/src/syscheck.c:322`) is the single entry point, gated by `__linux__ && ENABLE_AUDIT` and by config `whodata_provider == EBPF_PROVIDER` (`syscheck-config.h:103`, value `0`).
2. It calls `fimebpf_initialize(...)` passing **9 FIM callbacks** (see §4) then `ebpf_whodata_healthcheck()`.
3. `ebpf_whodata_healthcheck()` (`ebpf_whodata.cpp:660`): `check_invalid_kernel_version()` (hard floor **5.8**) → `init_libbpf()` (dlopen libbpf, resolve ~21 symbols) → `init_bpfobj()` → `init_ring_buffer()` → drives a synthetic create/modify/chmod/delete file and waits for events. On failure FIM **silently downgrades** `whodata_provider = AUDIT_PROVIDER` (`syscheck.c:330`).
4. `init_bpfobj()` (`ebpf_whodata.cpp:492`): opens `lib/modern.bpf.o`, calls `select_programs()` to choose which programs autoload, `bpf_object__load`, then attaches every autoloaded program. LSM-vs-kprobe decision is `is_bpf_lsm_active()` (reads `/sys/kernel/security/lsm` for token `bpf`). Among LSM programs it prefers the `_dpath` (`bpf_d_path`) variant and falls back **once** to the `_walk` variant if load fails (Amazon Linux 2/2023 reject `bpf_d_path` for `bpf_lsm_path_unlink`).
5. `ebpf_whodata()` (`ebpf_whodata.cpp:739`) is launched as a FIM thread from `run_check.c:320` (`w_create_thread(ebpf_whodata, NULL)`). It opens a second ring buffer with `handle_event`, spawns a **detached** worker thread running `ebpf_pop_events`, and polls the ringbuf until `m_fim_shutdown_process_on()`.

Attach points today (all file-activity only):
- kprobe: `vfs_open`, `vfs_unlink`, `vfs_rename`, `security_inode_setattr`
- LSM: `file_open`, `path_unlink`, `path_rename` (each `_dpath` + `_walk`)

## 3. The ring-buffer / event path

```
kernel BPF prog (submit_event)
  └─ struct file_event → BPF_MAP_TYPE_RINGBUF "rb" (8 MiB, 1<<23)
       └─ ring_buffer__poll (WAIT_MS=500) in ebpf_whodata() thread
            └─ handle_event() callback [ebpf_whodata.cpp:90]
                 ├─ confFn(e->filename) == fim_configuration_directory()  ← FIM filter, IN the callback
                 ├─ if (config->options & WHODATA_ACTIVE)
                 └─ copy into dynamic_file_event, push to fim::BoundedQueue kernelEventQueue
                      └─ ebpf_pop_events() worker thread [ebpf_whodata.cpp:603]
                           ├─ pop → build whodata_evt (strdup all strings, resolve user/group)
                           └─ m_fim_whodata_event(w_evt) → FIM's fim_whodata_event()
```

Two threads, one bounded queue between them. The queue (`BoundedQueue`, `bounded_queue.hpp`) drops on `push` when full (`ebpf_kernel_queue_full_reported` logs `FIM_FULL_EBPF_KERNEL_QUEUE` once). Max size = `syscheck.queue_size`. **This is the only backpressure mechanism and it is FIM-scoped.**

The `file_event` (kernel→user, `bpf_helpers.h:28`) and `dynamic_file_event` (heap C++ mirror, `bpf_helpers.h:42`) are the wire + internal shapes. `whodata_evt` (`syscheck-config.h:219`) is the FIM-domain shape the engine finally emits.

## 4. What is FIM-specific (the coupling)

The engine is not a neutral provider today — it reaches back into FIM through the `fimebpf` singleton (`ebpf_whodata.hpp`). Nine injected callbacks:

| Callback | FIM function | What it does | Coupling class |
|---|---|---|---|
| `m_fim_configuration_directory` | `fim_configuration_directory` | **kernel-event filter**: decides if a path is monitored (`WHODATA_ACTIVE`) | **HARD — filtering logic** |
| `m_fim_whodata_event` | `fim_whodata_event` | delivers the event INTO FIM | **HARD — sink** |
| `m_free_whodata_event` | `free_whodata_event` | frees the FIM event struct | domain type |
| `m_get_user` / `m_get_group` | `get_user`/`get_group` | uid→name, gid→name **enrichment** | enrichment (belongs in consumer) |
| `m_loggingFunction` | `loggingFunction` | agent logging | infra (keep) |
| `m_abspath` | `abspath` | resolve agent-relative paths | infra (keep) |
| `m_fim_shutdown_process_on` | `fim_shutdown_process_on` | shutdown flag → poll loop exit | **HARD — lifecycle owned by FIM** |
| `m_queue_size` | `syscheck.queue_size` | backpressure sizing | config |

Additional FIM-specific facts baked into the engine:
- **Event shape is `whodata_evt`** — a FIM/audit domain type (has `audit_uid`, `effective_uid`, `mask`, `scan_directory`), not a raw kernel event.
- **Filtering is FIM policy** — `handle_event` calls `fim_configuration_directory` and tests `WHODATA_ACTIVE` inside the ringbuf callback. A neutral provider cannot know FIM's directory table.
- **Enrichment is done in the engine** — uid/gid→name resolution (`ebpf_pop_events`), which is a consumer concern.
- **Event classes are file-only** — no exec, no network. `submit_event` only ever emits file activity.
- **Lifecycle is FIM's** — the poll loop, the worker thread, and shutdown are driven by FIM's thread and FIM's shutdown flag. There is no independent provider lifecycle.
- **Global singletons** — `global_obj`, `g_bpf_lsm_active`, `kernelEventQueue`, `bpf_helpers`, `fimebpf::instance()` are process-global. Fine for one consumer; blocks a second consumer today.
- **Config lives under `<syscheck>`** — `whodata_provider` is a syscheck config bit (`syscheck-config.h:379`); there is no standalone provider config.

## 5. Every consumer reaching into the engine

Only ONE consumer today: FIM/syscheck.

| Touch point | File:line | Reaches for |
|---|---|---|
| enable + healthcheck + downgrade | `src/syscheckd/src/syscheck.c:322-332` | `fimebpf_initialize`, `ebpf_whodata_healthcheck` |
| provider capability gate | `src/syscheckd/src/main.c:294-299` | `EBPF_PROVIDER`, `FIM_ERROR_EBPF_NOT_SUPPORTED` |
| run engine thread | `src/syscheckd/src/run_check.c:317-322` | `ebpf_whodata` |
| config surface | `src/syscheckd/src/config.c:297` | `whodata_provider` → `"ebpf"`/`"audit"` |
| include of engine ABI | `create_db.c:20`, `run_check.c:26`, `syscheck.c:20` | `ebpf/include/ebpf_whodata.h` |
| build link | `src/syscheckd/CMakeLists.txt:116-117` | `add_subdirectory("src/ebpf")`, link `fimebpf` |
| event sink | `fim_whodata_event()` (`syscheck.h:240`) | consumes `whodata_evt` |

## 6. Coupling-extraction map (touch-point → target boundary → refactor action)

Target boundary names used below (per ADR-001 option (b) — per-module integration):
- **LIBRARY** = the extracted reusable eBPF component, shipped as a shared library and **linked into each consuming module's own process** (FIM = `wazuh-syscheckd`, Syscollector = inside `wazuh-modulesd`). It is **not** a separate provider process; each linking module loads only the hooks it needs and owns its own ring buffer + consume loop. The load/attach/capability-probe/fallback logic lives here once (shared), the programs load per-module.
- **CONSUMER** = the module linking the LIBRARY (FIM / Syscollector) — installs hooks, consumes its own stream, enriches.
- **CONTRACT** = the raw-event layout + in-process API the LIBRARY exposes (see `03-event-contract-spec.md`).

> The extraction work is identical to what a standalone provider would have needed — cut the FIM callbacks, move path policy + uid/gid enrichment to the consumer, add correlation keys, add exec/network programs. What (b) changes is **where the extracted component lives**: a library linked per-module, not a central provider process. Rows below tagged PROVIDER in an earlier revision now read LIBRARY.

| # | Touch point (current) | Target boundary | Refactor action |
|---|---|---|---|
| C1 | `fimebpf` singleton with 9 FIM callbacks (`ebpf_whodata.hpp`) | LIBRARY internal | Delete the singleton. Replace with a neutral in-process library API: `rt_open(filter) → handle` / `rt_poll(handle, cb)` / `rt_close`. No consumer-specific callbacks baked in; the linking module supplies its own sink. |
| C2 | `handle_event` calls `fim_configuration_directory` + tests `WHODATA_ACTIVE` (`ebpf_whodata.cpp:101`) | CONTRACT (filter) + CONSUMER | Move path-policy OUT of the engine. Engine filters only by the neutral subscription filter (event type / path prefix / cgroup scope). FIM applies `WHODATA_ACTIVE` in its own subscriber callback. |
| C3 | uid/gid→name enrichment in `ebpf_pop_events` (`:626,:628`) | CONSUMER | Remove from engine. Emit raw uid/gid in the contract; each consumer resolves names itself (reuse existing `get_user`/`get_group`). |
| C4 | Emits `whodata_evt` (FIM domain type) | CONTRACT | Replace with the neutral flat `rt_event` family (file/exec/net) from the event-contract spec. FIM adapts `rt_event`→`whodata_evt` in a thin shim. |
| C5 | `m_fim_shutdown_process_on` drives poll loop (`:609,:753`) | LIBRARY / CONSUMER | The linking module owns its own stop flag; the library exposes a stop that unwinds attach + ring buffer. No cross-module lifecycle to coordinate (each module runs its own). |
| C6 | `ebpf_whodata()` launched as a FIM thread (`run_check.c:320`) | CONSUMER | Each module drives its own load/attach/consume loop on its own thread (FIM already does; Syscollector adds one). No central process starts it. |
| C7 | Single global `kernelEventQueue` + one-shot full-report flag | LIBRARY (per-module) | Each module owns its own bounded queue + ring buffer, so there is **no cross-module starvation** to solve under (b). Keep drop-visibility (per-module drop counter surfaced to that module's telemetry) — a dropped event is still a missed state. |
| C8 | Globals `global_obj`, `g_bpf_lsm_active`, `bpf_helpers` | LIBRARY instance (handle) | Encapsulate in a per-`rt_open` handle so a module holds its own instance (multiple modules = multiple handles in different processes). No process-global singleton. |
| C9 | Config bit `whodata_provider` under `<syscheck>` (`syscheck-config.h:379`) | CONSUMER config | Each module keeps its own eBPF switch: FIM's `whodata_provider=ebpf` stays as-is; Syscollector gets an analogous option. No central provider config block. |
| C10 | Healthcheck writes/deletes a real file & waits (`ebpf_whodata_healthcheck`) | LIBRARY | Keep as a library self-test at load, but it must not depend on FIM's `abspath`/config; use a library-owned temp path. Each linking module runs it on its own load. |
| C11 | Build: `fimebpf` sub-library linked into `wazuh-syscheckd` (`CMakeLists.txt:116`) | LIBRARY | Generalise into **one shared library** (`libwazuh_ebpf`) built once and **linked by both** FIM and Syscollector. Each links the library and loads its own programs (per (b)); the library carries the shared loader/capability-probe/fallback logic so the two per-module loaders cannot diverge (ADR-001 risk 3). |
| C12 | Only file-activity programs exist (`modern.bpf.c`) | LIBRARY (new programs) | Add exec (tracepoint `sched_process_exec`) and network (connect/accept/bind) programs. Each module autoloads only its own classes: FIM = file, Syscollector = exec + network (disjoint sets → no duplicated hooks). See event-contract spec §Event classes. |
| C13 | `file_event` carries no correlation keys (no cgroup id, no ns inodes) | CONTRACT + `modern.bpf.c` | Extend the kernel event with `cgroup_id` (`bpf_get_current_cgroup_id`) and mount/pid/net ns inodes (`task->nsproxy->*_ns->ns.inum`). Consumers correlate to containers themselves. Must be OPTIONAL / zero on host. |

**Extraction shape**: C1–C5 convert the engine from "push into FIM" to a neutral in-process event source; C6–C8 make lifecycle and instance per-module (each module owns its own); C9 keeps config per-module; C10–C11 ship the extracted logic as one shared library both modules link; C12–C13 add the event classes and correlation keys the objective requires. The extraction is the same regardless of (a)/(b); (b) only changes that the component is a per-module library rather than a central provider. None of these introduce a new external dependency.

## 7. Notable current-code hazards to preserve during extraction

- **Verifier portability is hard-won.** `modern.bpf.c` encodes kernel-version-specific arg layouts (`vfs_unlink`/`vfs_rename` pre/post 5.12/6.3; `security_inode_setattr` pre/post 6.0) and uses `PT_REGS_PARM*_CORE` specifically to pass the strict 6.8 verifier. **Do not rewrite these blindly.** New exec/net programs must get the same per-kernel care (see `05-compatibility-matrix.md`).
- **`bpf_d_path` is not universally allowed.** The `_dpath`/`_walk` dual-variant + single fallback is load-bearing for Amazon Linux. Any new path-emitting program needs the same fallback story.
- **`.rodata.str1.1` avoidance** (`modern.bpf.c:334`) — empty-string writes are done by hand to keep libbpf <0.6 happy. Keep this idiom.
- **8 MiB ringbuf.** Under (b) each module owns its own ring buffer (FIM one, Syscollector one) — no shared buffer to demux. Size per module to its own event rate. See `04-lifecycle-backpressure.md`.

## 8. Open questions raised by the audit (coordinate)

- **Q-A1** Does Syscollector want the SAME raw stream or a pre-aggregated one? The contract carries raw events; #37534 owns realtime-vs-scheduled selection. → coordinate with IT Hygiene spike owner.
- **Q-A2** Path resolution (kernel path → logical/host path) is FIM-owned (#, out of scope). The contract must carry the **raw kernel path** and enough (mount ns inode) for FIM to resolve. → confirm with FIM spike owner that mount-ns inode is sufficient.
- **Q-A3** Back-compat of `whodata_provider=ebpf` config semantics — does keeping it as "subscribe to provider" satisfy existing user configs? → the team.
