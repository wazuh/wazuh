# Lifecycle & Backpressure — per-module eBPF component (#37396)

Covers load/attach/detach/reload, ring-buffer sizing, drop policy, and graceful degradation. Builds on the current engine's mechanisms (`01-current-state-audit.md`).

**Boundary (ADR-001 = option (b)):** each module links the shared eBPF library and owns **its own** load → attach → ring buffer → consume loop, in its own process. There is **no central provider, no dispatcher, no cross-module fan-out, no IPC**. The lifecycle below therefore describes **one module's own instance**; every module runs its own copy independently. The earlier (a)-oriented framing (shared ringbuf demuxed to per-subscriber queues, cross-process reconnect) no longer applies — but the two requirements that matter under either boundary, **drop visibility** and **graceful degradation**, are retained and simplified.

## 1. Lifecycle state machine (per module instance)

```
             ┌─────────┐  caps/kernel missing        ┌──────────┐
   start ───▶│  PROBE  │────────────────────────────▶│ DISABLED │ (log once, module keeps running w/o eBPF)
             └────┬────┘                              └──────────┘
                  │ ok (healthcheck passes)                 ▲
                  ▼                                          │ unrecoverable load/attach error
             ┌─────────┐   config reload                     │
             │ RUNNING │◀──────────────┐                     │
             └────┬────┘               │                     │
                  │ reload             │ (re)attach ok       │
                  ▼                    │                     │
             ┌─────────┐               │                     │
             │RELOADING│───────────────┘                     │
             └────┬────┘  attach fails ───────────────────────┘
                  │ stop
                  ▼
             ┌─────────┐
             │STOPPING │  detach, free ringbuf, close obj, dlclose libbpf
             └─────────┘
```

### PROBE (module load)
1. Feature probe via the **shared loader** (`05-compatibility-matrix.md`): ringbuf, CO-RE/BTF, LSM-active, `bpf_d_path` allowed, `RLIMIT_MEMLOCK` raised (`07-` finding 3). Doing this in the shared library is what keeps two modules' loaders from diverging (ADR-001 risk 3).
2. `dlopen` libbpf, resolve symbols (today's `init_libbpf`).
3. Autoload **only this module's** `type_mask` programs (`select_programs()`): FIM → file hooks, Syscollector → exec+network hooks.
4. Load + attach. Run the self-test healthcheck against a **library-owned** temp path (not FIM's).
5. On any failure → **DISABLED** for this module: log once, never crash the agent (hard constraint). The module falls back to its non-eBPF path (FIM → audit provider, exactly like today's `whodata_provider = AUDIT_PROVIDER` downgrade at `syscheck.c:330`). A disabled/failed module does not affect any other module — they are separate processes with separate instances.

### RUNNING
- The module owns one poll thread on its own `ring_buffer__poll` (like `ebpf_whodata()` today), delivering events to the module's own sink via `rt_poll`.
- No shared registry, no demux: the module is the sole consumer of its own stream.

### RELOADING (this module's config reload)
- **Requirement:** a config reload within a module must not lose events unnecessarily, and — because modules are independent processes — **cannot** affect another module's stream at all (that isolation is free under (b)).
- Path-prefix changes are **user-space only** → swap the filter the module applies in its own consume loop; zero kernel impact.
- `type_mask` grows (module now wants another class) → attach the *additional* programs; existing links untouched, no gap for the classes already flowing.
- `type_mask` shrinks → detach only the dropped class's programs.
- cgroup-scope change → update the cgroup-id allowlist **map** in place (`bpf_map_update_elem`); no reattach. This is why cgroup filtering lives in a map, not in program code.

### STOPPING
- Signal poll thread, `ring_buffer__free`, detach + `bpf_object__close`, `dlclose`. Mirrors today's `ebpf_whodata()` teardown (`ebpf_whodata.cpp:761`), scoped to this module's instance.

## 2. Ring-buffer sizing (per module)

- **Each module owns its own ring buffer** (`BPF_MAP_TYPE_RINGBUF`, today 8 MiB `modern.bpf.c:66`). Two modules = two buffers (ADR-001 risk 4, accepted). Size each to *its own* event rate — FIM's file-create rate and Syscollector's exec/connect rate differ, so per-module sizing is an advantage, not just a cost.
- Sizing rule: `size ≥ peak_events_per_poll_interval × avg_event_size × safety`. With `WAIT_MS=500` poll and bursty storms, 8 MiB holds ~tens of thousands of ~300-byte events — adequate, but make it **configurable per module** and revisit against `06-performance-budget.md`. Consider adaptive poll interval under load to bound residency.
- The per-CPU path-reconstruction heaps (`heaps_map`, `full_path_map`/`dpath_map`, `cwd_heap`) are per-instance (each module's loaded object has its own).

## 3. Backpressure & drop visibility (within a module)

There is no cross-module starvation to solve under (b) — each module drains its own ring buffer on its own thread. What remains is making a module's **own** drops visible, because a dropped event is a missed FIM/Syscollector state.

- **The poll thread must never block.** It drains the kernel ring buffer and hands each event to the module's sink; if the module's internal work queue (the existing `fim::BoundedQueue`, `bounded_queue.hpp`) is full, drop-on-full rather than block, so the kernel ring buffer keeps draining. This is the same isolation property as before, now purely intra-module.
- **Drop policy:** drop-on-full, increment the module's `dropped` counter, set `RT_F_DROPS_BEFORE` on the next delivered event so loss is **visible in-band**. Today it is only a one-shot log line (`FIM_FULL_EBPF_KERNEL_QUEUE`); the per-module `dropped` count is strictly better.
- **Kernel ring-buffer overflow** (producer faster than the poll thread) is distinct: `bpf_ringbuf_reserve` returns NULL in-kernel (event never emitted). Surface it via a BPF counter map read each poll, exposed as a per-module drop metric. VERIFY the counter approach on-kernel.

## 4. Isolation invariants

1. Poll-thread progress is independent of the module's downstream work (non-blocking hand-off, drop-on-full).
2. A module's backlog bounds only its own queue memory.
3. **Module isolation is structural under (b):** modules are separate processes with separate instances, so one module being slow, disabled, or crashed cannot affect another's stream — no shared ring buffer, no shared queue, no shared loader state at runtime.

## 5. Graceful degradation matrix (per module)

| Condition | Behavior | Never |
|---|---|---|
| kernel < floor / no ringbuf / no BTF | PROBE → DISABLED for this module, log once | crash the agent |
| LSM not active | fall back to kprobe programs (today's `is_bpf_lsm_active()` path) | fail |
| `bpf_d_path` rejected for a hook | fall back to `_walk` variant (today's single-retry) | fail |
| missing `CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_ADMIN` | PROBE fails cleanly → DISABLED; log the exact missing cap | crash |
| `RLIMIT_MEMLOCK` too low (5.10-class) | raise it in the loader before map create (`07-` finding 3) | fail on a fixable EPERM |
| one program fails to attach | if it belongs to an unused class, skip; if core to this module and no fallback, DISABLED | attach partial and lie |
| ringbuf poll returns <0 | log, attempt one ringbuf re-create; if it fails, DISABLED | busy-loop |
| module's own queue is full | drop-on-full, count drops, flag next event | stall the poll thread / kernel ring |

## 6. Open questions / coordinate

- **OQ-L1** Adaptive poll interval vs fixed `WAIT_MS=500` under load — measure in `06-`.
- **OQ-L2** Should each module expose its eBPF drop metrics via the module `query` hook (`wm_context.query` for Syscollector; an equivalent for FIM) for observability? Recommend yes.
- **OQ-L3** Shared loader library ownership: the capability-probe/fallback/`RLIMIT_MEMLOCK` logic must live once and be linked by both modules (ADR-001 OQ-1). Confirm the library boundary with implementation owners.
