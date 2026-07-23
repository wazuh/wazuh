# 06 — Performance Budget (Spike #37396, HALF B)

Scope: cost model for the **reusable eBPF component each module links** (ADR-001 option (b)), emitting **file-open/create/write + unlink/rename + exec + (future) connect**. FIM installs the file hooks and Syscollector the exec/network hooks, each into its own per-module ring buffer (see §4).

Legend: **[V]** verified w/ citation · **[EST]** engineering estimate · **[TBM]** to be measured.

---

## 1. Event-rate model

Public anchors:
- Falco modern-eBPF sustained **>164K kernel events/sec per CPU on a 128-CPU box** without drops after tuning. **[V]** [Falco performance testing](https://falco.org/blog/falco-performance-testing/).
- eBPF runtime-security agents run at **~1–5% CPU** overhead in production; Falco 0.40 default modern driver 1–5%, Tetragon "thousands of ev/s, negligible overhead". **[V]** [safeguard.sh Tetragon vs Falco](https://safeguard.sh/resources/blog/tetragon-vs-falco-runtime-security-2026), [Falco modern-bpf](https://falco.org/blog/falco-modern-bpf/).
- Tetragon key property: **in-kernel filtering → near-zero cost for non-matching events**; Falco cost scales with total event volume regardless of match. **[V]** same source. This is the single most important design lesson.

Per-class rates (our provider only cares about a few event kinds, NOT all syscalls):

| Class | Idle host | Typical server | Busy build/CI node | Notes |
|---|---|---|---|---|
| file **open** (all) | 10²–10³/s | 10³–10⁴/s | **10⁴–10⁵/s** | [EST] compilers/linkers open thousands of headers; git/rsync bursts |
| file **create/write/unlink/rename** (FIM-relevant subset) | 1–10/s | 10²–10³/s | **10³–10⁴/s** peaks | [EST] most opens are read-only → filtered in kernel (see §3) |
| **exec** (sched_process_exec) | <1/s | 1–50/s | **10²–10³/s** | [EST] `make -jN`, shell scripts spawn heavily |
| **connect/accept** | <1/s | 10–10²/s | **10²–10³/s** | [EST] chatty microservices / package fetches |

Design target: the busy build node worst case ≈ **10⁵ raw file-opens/s** pre-filter, dropping to **~10³–10⁴/s** FIM-relevant post-filter, plus **~10³/s** exec. That is well inside Falco's demonstrated headroom **per CPU**, but each module's own ring buffer (not per-CPU) is the constraint (§4).

---

## 2. Per-event CPU budget

- BPF program cost per event (read args, CO-RE derefs, path resolve, ringbuf reserve/commit): **~0.5–3 µs** on a modern x86 core. **[EST]** (path resolution via `bpf_d_path`/dentry walk dominates; exec/connect are cheaper, no path walk).
- At 10⁵ file events/s × ~2 µs ≈ **0.2 CPU-seconds/s ≈ 20% of one core** *before* filtering — unacceptable if unfiltered. After in-kernel filtering to ~10⁴/s FIM events → **~2% of one core**. **[EST]**
- Userspace cost per module (its own ringbuf poll + parse) is the other half; keep it O(post-filter events), never O(raw).

**Budget we can absorb**: target **< 3% of one core** aggregate for the provider on a typical server, **< 1 core** worst case on a busy build node. Achievable only with aggressive in-kernel filtering.

---

## 3. Where to filter — kernel-side first, always

Current code already does the two highest-value filters **in-kernel**: **regular-files-only** and **creation/write-only** (drops read-only opens). Keep and extend:

Kernel-side (drop before ringbuf reserve — cheapest possible):
1. **Regular files only** (`S_ISREG`) — already done. Kills device/proc/sock noise. **[V-code]**
2. **Creation/write intent only** — already done. Kills the ~90% read-only open flood. **[V-code]**
3. **cgroup scope filter**: if a consumer only wants specific cgroups/containers, match `bpf_get_current_cgroup_id()` against a `BPF_MAP_TYPE_HASH` allow/deny map in-kernel. Tetragon-style. **[EST]** biggest win on container hosts.
4. **Path-prefix filter**: FIM watches a bounded set of directories. Push a prefix/inode allowlist map (or dev+ino of watched dirs) into the kernel and drop non-matching paths **before** the expensive `bpf_d_path`. This inverts the cost: resolve path only for candidates. **[EST]** — high value, needs POC.
5. **Event-type autoload per module**: each module loads only its own classes (FIM wants file+setattr; Syscollector wants exec), so a module never attaches or reserves records for a class it does not consume.

Userspace-side (per module: dedup, enrich):
- Each module runs one reader thread draining its own ringbuf; no cross-module fan-out. One reader per buffer.
- Enrichment (uid→name, cgroup id→path, pid→container) done once in the module's userspace, cached.
- De-dup coalescing of write bursts to the same inode within a time window (FIM cares about "changed", not every write).

Rule of thumb (from Tetragon): **every event that leaves the kernel must have a subscriber**. Filtering in userspace is a last resort.

---

## 4. Ring buffer sizing

Current: **single shared `BPF_MAP_TYPE_RINGBUF`, 8 MB (`1<<23`)**, MPSC — all CPUs write one buffer, one userspace consumer. **[V-code]**

Contrast: **Falco default = 8 MB *per online CPU*** (128-CPU box → up to 1 GB), tunable via `syscall_buf_size_preset`, and can raise to 128 MB/CPU to eliminate drops. **[V]** [Falco modern-bpf 0.35](https://falco.org/blog/falco-modern-bpf-0-35-0/), [Falco issue #813](https://github.com/falcosecurity/falco/issues/813).

The single shared 8 MB buffer above is today's FIM-only shape. Under ADR-001 option (b), **per-module ring buffers are structural**: each module (FIM, Syscollector) links the eBPF library and owns its own buffer, in its own process. So this is not a shared-vs-split choice, and the "noisy-neighbor between consumers" problem (one buffer where a Syscollector exec storm evicts FIM file events) is **absent by construction**. The design question reduces to **per-module sizing**, each buffer sized to its own module's event rate.

Per-buffer characteristics (apply to each module's own buffer):
- **Pro**: simple, one poll loop per module, low memory, MPSC ringbuf is lock-light and self-pacing (commit only notifies if the consumer caught up). **[V]** [kernel ringbuf docs](https://www.kernel.org/doc/html/next/bpf/ringbuf.html).
- **Con — head-of-line + burst drops within a module**: on a many-core busy node all CPUs contend on that module's one buffer. At ~64–256 B/record, 8 MB holds ~**32K–128K records**. A 10⁵ ev/s burst fills it in **<1 s** if that module's consumer stalls (GC pause, disk I/O in FIM). `bpf_ringbuf_reserve` returns NULL on full → **silent drop**; each module must count drops (a `dropped` counter map) and expose them. **[EST]**

Per-module sizing:
- Size each module's buffer to its **own** event rate (§1): FIM's file-create rate and Syscollector's exec/connect rate differ, so they need not be equal. Baseline **16 MB** each, tunable; raise for a hot module (up to the 16–32 MB range, or higher for a burst-heavy build node). **[EST]**
- **Per-CPU buffers (Falco-style)** — best scalability, most memory, most complex — remain overkill for an agent that already filters hard in-kernel; not needed unless per-module measurement shows single-buffer contention on a many-core node. **[EST]**
- Always maintain and expose a **drop counter** per module; drop behavior must be observable, never silent.

---

## 5. Concrete filtering recommendations (per-module cheapness)

1. **In-kernel subscription mask**: config map keyed by event-class; program reserves a record only if ≥1 consumer subscribed. Prevents paying for exec records when only FIM is active, and vice-versa.
2. **In-kernel path/inode allowlist for FIM**: push watched dirs (dev+ino) to a hash map; drop + skip `bpf_d_path` for non-watched paths. Turns the file class from O(all writes) into O(writes-in-watched-dirs). Biggest single win.
3. **In-kernel cgroup allow/deny** for container-scoped monitoring.
4. **Coalesce writes** to same inode in-kernel with a short-lived per-inode timestamp map (LRU hash) to suppress write-storms to the same file; emit "changed" once per window.
5. **Each module's own ring buffer + its own reader loop**; enrichment cached in that module's userspace (structural under (b), see §4).
6. **Expose metrics**: events emitted/class, records dropped (ringbuf full), map-full evictions, and CPU self-usage — so the budget is verifiable in the field, not just estimated.

---

## 6. What must be MEASURED [TBM]
- Real per-event BPF cost (dpath vs walk vs kprobe) via `bpftool prog profile` / `perf` on RHEL 8 (kprobe path) and Ubuntu 24.04 (LSM dpath). Estimates in §2 are unvalidated.
- Drop rate of a module's own 8 MB buffer under a `make -j$(nproc)` kernel build on a 16–32 core node.
- Post-filter FIM event rate on a representative production host to size buffers correctly.
- Overhead delta of path-prefix in-kernel filtering vs unconditional `bpf_d_path`.

---

## Sources
- [Falco — Performance testing (164K ev/s/CPU)](https://falco.org/blog/falco-performance-testing/)
- [Falco — Modern eBPF probe ready to shine 0.35](https://falco.org/blog/falco-modern-bpf-0-35-0/) · [Getting started with modern BPF probe](https://falco.org/blog/falco-modern-bpf/)
- [Falco issue #813 — buffer size adjustment](https://github.com/falcosecurity/falco/issues/813)
- [Falco — Dropping syscall events](https://falco.org/docs/troubleshooting/dropping/)
- [safeguard.sh — Tetragon vs Falco 2026 (in-kernel filtering, overhead)](https://safeguard.sh/resources/blog/tetragon-vs-falco-runtime-security-2026)
- [BPF ring buffer — kernel.org](https://www.kernel.org/doc/html/next/bpf/ringbuf.html)
