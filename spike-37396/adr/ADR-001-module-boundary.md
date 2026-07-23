# ADR-001 — Module boundary for the eBPF runtime-telemetry component

**Status:** Decided — **option (b), per-module eBPF integration.** Decision made by the team in project review; this ADR was reworked to match (it originally proposed (a) — see *History* below). **Needs review by:** FIM spike + IT Hygiene (Syscollector) spike + the team (see OQ-5).

## Context

The objective (#37203) turns the eBPF engine — today embedded in FIM/syscheck — into a reusable runtime-telemetry component consumed by FIM and Syscollector (and future modules). The open question was the module boundary:

- **(a)** ONE engine instance in the agent that loads the BPF programs **once** and fans out to multiple subscribers (in-process + IPC across daemons).
- **(b)** each module links the eBPF component and loads **its own** BPF programs — only the hooks that module needs.

### What "a module" structurally is (grounding)

The agent is **multi-process** (`src/init/wazuh-client.sh:20`):

```
DAEMONS="wazuh-modulesd wazuh-logcollector wazuh-syscheckd wazuh-agentd wazuh-execd"
```

- **FIM = `wazuh-syscheckd`** — its own OS process, links the eBPF engine as a sub-library today (`run_check.c:320`).
- **Syscollector = a wmodule** (`wm_context`, `src/wazuh_modules/wmodules_def.h:35`) on a pthread **inside `wazuh-modulesd`** — a different OS process.

The two consumers do **not** share an address space. That fact is what makes (b) attractive: under (a) a shared stream must cross a process boundary (IPC), whereas under (b) each daemon simply links the eBPF component it already needs and loads its own programs — no cross-process transport at all.

## Decision

**Adopt option (b): each module links the eBPF component and installs only the hooks it needs; there is no central provider and no shared event stream.** FIM loads file-activity programs; Syscollector loads process-exec + network programs. A module that is disabled installs no hooks.

### Rationale (the team's rationale, from project review)

> "Vemos que es posible instalar una integración BPF por módulo. Esto nos simplificaría mucho el diseño (mejor que un solo módulo con integración BPF + forwarding/broadcasting a resto de módulos). Cada módulo usa los hooks que necesita. Si un módulo se deshabilita, directamente no instala los hooks. Evitamos IPC masivo (y colas extra). Creemos que este camino merece más la pena."

Distilled, the drivers are:
1. **Design simplicity.** No central broker, no forwarding/broadcasting layer, no subscription/fan-out demux. Each module owns its own load → attach → ring-buffer → consume path, which is essentially the shape FIM already has today.
2. **No IPC, no extra queues.** The single biggest cost the (a) design carried was moving events across the `wazuh-syscheckd` ↔ `wazuh-modulesd` process boundary (a unix socket or shared-memory ring, plus per-subscriber queues and reconnect logic). Under (b) that entire layer disappears — events are consumed in the same process that produced them.
3. **Disable = no hooks.** If a module is disabled it simply never loads its programs; there is no always-on provider attaching hooks nobody consumes. Kernel cost tracks exactly what is enabled.

### Why the main objection to (b) is largely void here

The previous version of this ADR rejected (b) chiefly on **duplicated kernel cost** (two modules → two programs on every hook → double per-event overhead → N× ring buffers). That objection assumed the two modules want the **same** hooks. They do not:

- **FIM** needs **file activity** — `lsm/file_open` / `kprobe/vfs_open`, unlink, rename, setattr.
- **Syscollector** needs **process exec + network** — `tracepoint/sched_process_exec`, socket/connect/accept hooks.

These hook sets are **largely disjoint**. Where the sets don't overlap — which is the common case for the two known consumers — there is **no duplication at all**: each hook is installed exactly once, by the one module that wants it. The "double cost on every syscall" scenario only materialises on a hook two modules both request, which today is **none**. This removes most of the force of the original objection and is the empirical reason (b) is cheaper than the earlier analysis assumed.

## Consequences / risks to mitigate

The costs the earlier analysis documented are real; under (b) they become accepted trade-offs with mitigations, not reasons to reject.

1. **Privilege is no longer confined to one process.** BPF loading needs `CAP_BPF` + `CAP_PERFMON` (≥5.8) or `CAP_SYS_ADMIN` (older) — **measured present on every capable kernel** (`07-vm-validation-evidence.md`). Under (b) **both** `wazuh-syscheckd` **and** `wazuh-modulesd` must hold these capabilities, instead of a single confined `wazuh-ebpfd`. *Accepted trade-off.* Mitigation: grant the caps narrowly via systemd (`AmbientCapabilities=`/`CapabilityBoundingSet=` limited to `CAP_BPF CAP_PERFMON CAP_DAC_READ_SEARCH`, not full `CAP_SYS_ADMIN`, on kernels ≥5.8), document the MAC policy delta (ADR-002 D5), and keep the BPF-loading surface inside the shared library (next point) so it is auditable in one place even though two processes invoke it.
2. **Duplication bites only on a shared hook.** If a future module wants an event class another module already installs (e.g. a second consumer of file activity, or FIM and Syscollector both wanting `security_inode_*`), that hook gets **two BPF programs attached and two ring buffers**, doubling per-event cost on that hook and adding a second ring buffer's memory. *Mitigation:* when a real overlap appears, revisit just that hook — either promote that one event class to a shared producer, or dedupe at the program level. The architecture doesn't forbid a later per-hook merge; it just doesn't pay for one up front. Document known/potential overlaps in the implementation tickets.
3. **Two loaders could diverge.** The `_dpath`/`_walk` LSM fallback and the per-kernel arg-layout handling (pre/post 5.12/6.3 `vfs_*`, 6.0 `security_inode_setattr`; `01-current-state-audit.md §7`) are load-bearing and hard-won. Under (b) each module runs its **own** loader and could reach a **different** capability conclusion on the same host (e.g. one picks `_dpath`, the other `_walk`). *Mitigation — strong recommendation:* ship the load/attach/capability-probe/fallback logic as **one shared library** (`libwazuh_ebpf` or similar) that both modules link. The **programs** load per-module (per (b)), but the **decision logic** — kernel capability probing, LSM-vs-kprobe selection, `_dpath`/`_walk` fallback, `RLIMIT_MEMLOCK` bump (`07-` finding 3) — exists **once**. This keeps (b)'s simplicity while eliminating the divergence risk.
4. **Ring-buffer memory is per-module.** Each module owns its own ring buffer (today 8 MiB, `modern.bpf.c:66`) rather than one shared buffer. Two modules = two buffers. *Accepted:* memory is cheap relative to the IPC machinery (b) avoids, and per-module sizing can track each module's event rate independently (`06-performance-budget.md`).
5. **The two-process concurrent load is untested (validation gap, not a design flaw).** Two independent processes each loading their own BPF programs on disjoint hooks, concurrently — the core mechanic of (b) — was not exercised; all on-kernel runs (`07-vm-validation-evidence.md`) loaded a single object in a single process. The measured evidence (kernel capabilities, both attach paths, `cgroup_id`/`st_ino` equality, real-container correlation) is boundary-independent and stands, but the specific FIM-in-`wazuh-syscheckd` + Syscollector-in-`wazuh-modulesd` concurrency has not been run. *Mitigation:* straightforward to test (two PoC instances with different `type_mask`s on one VM) and worth doing before implementation.

**Net:** (b) trades single-process privilege confinement and shared-buffer memory for a materially simpler design with no IPC. Given the disjoint hook sets, the kernel-cost objection is mostly void; the remaining risks (privilege sprawl, loader divergence) are mitigated by narrow systemd caps + a shared loader library.

## Structural mapping onto the agent

- **No new daemon.** Each existing daemon (`wazuh-syscheckd`, and Syscollector inside `wazuh-modulesd`) links the shared eBPF library and drives its own load/attach/consume loop — the shape FIM already has (`ebpf_whodata.cpp`), generalised.
- The extracted component is a **library**, not a service: a neutral in-process API (`rt_open(filter) → handle`, `rt_poll(handle, cb)`, `rt_close`) plus the shared loader. The programs and ring buffer live inside the linking module's process.
- Config: each module keeps its own eBPF switch (FIM's `whodata_provider=ebpf` stays as-is; Syscollector gets an analogous option). No central `<runtime_telemetry>` block.

## Open questions

- **OQ-1** Shared loader library vs each module vendoring its own copy of the load/fallback logic — strongly recommend the shared library (risk 3). Confirm with the implementation owners.
- **OQ-2** systemd capability scoping: can both `wazuh-syscheckd` and `wazuh-modulesd` run with `CAP_BPF`+`CAP_PERFMON` only (no `CAP_SYS_ADMIN`) on the ≥5.8 fleet? Validate on a real service unit (host-package model). — packaging owners.
- **OQ-3** Which event classes might two modules legitimately both want (risk 2)? Enumerate now so overlaps are a known list, not a surprise. — FIM + IT Hygiene owners.
- **OQ-4** Does any consumer actually need another consumer's events (the original fan-out use case)? If yes for a specific class, that class — and only that class — may warrant a shared producer; the rest stay per-module.
- **OQ-5 — three parts of the issue text assume option (a) and need restating.** The chosen boundary (b) leaves the following stale: (i) parent objective NFR4 ("independent eBPF Module ... shared runtime telemetry provider"); (ii) this issue's title ("standalone runtime telemetry provider"); (iii) acceptance criterion 5 ("two independent consumers with distinct filters over one event stream" — under (b) there is no shared stream by design). The spike's Scope explicitly allowed either shape ("in-process library vs separate process/daemon"), so the architecture answer is in scope; the wording of the objective, title and criterion is not ours to change. Flagged for the team to restate. Not silently dropped, not claimed met.

## History — why this ADR reversed

The first version of this ADR (spike analysis) concluded **option (a)**: one provider loading BPF once and fanning out, placed in a dedicated `wazuh-ebpfd` daemon for capability confinement and crash isolation. Its reasoning rested on treating "duplicated kernel cost" and "privilege sprawl" as decisive against (b).

That analysis was **superseded by the team's decision** for (b), on the grounds quoted above. The reversal is sound because the strongest (a)-argument — duplicated kernel cost — assumed overlapping hook sets, whereas FIM's and Syscollector's hook sets are **disjoint** (see "Why the main objection to (b) is largely void"), so the duplication mostly does not occur. In exchange, (b) removes the entire IPC/fan-out/queue layer that (a) required to cross the `syscheckd`↔`modulesd` process boundary — a large simplification. The costs (a) cited as fatal are retained above as **managed risks**, not discarded: they were real, they are just outweighed here and mitigable (narrow caps + shared loader). Keeping this history so a future reader sees the trade changed, not that the earlier work was wrong to surface those costs.
