# Spike #37396 — Extract the eBPF engine into a reusable runtime-telemetry component

Parent objective #37203. RESEARCH + DESIGN spike. Deliverables are markdown + ADRs + one throwaway PoC. All code claims are grounded in real files on branch `fix/6761-...` (paths cited inline).

## Highest-priority decision (decided by the team)

**The module boundary is option (b): each module links the eBPF component and installs only the hooks it needs — FIM loads file-activity programs, Syscollector loads process-exec + network programs. There is no central provider and no shared event stream.** A disabled module installs no hooks. Decided by the team on the grounds of design simplicity, no IPC / no extra queues, and disable-means-no-hooks. See **`adr/ADR-001-module-boundary.md`**.

> **Honest note:** this spike's own analysis originally reached the **opposite** conclusion (option (a): one provider loading BPF once and fanning out via IPC), and was **superseded** by the team's decision. The reversal holds up because FIM's and Syscollector's hook sets are **largely disjoint**, so the "duplicated kernel cost" that argued for (a) mostly does not occur — while (b) removes the entire IPC/fan-out/queue layer (a) needed to cross the `wazuh-syscheckd`↔`wazuh-modulesd` process boundary. The costs (a) cited (privilege in two processes, per-module ring buffers, two loaders that could diverge) are retained in ADR-001 as **managed risks** with mitigations (narrow systemd caps; a **shared loader library** so capability-probe + `_dpath`/`_walk` fallback logic exists once), not discarded.

Key structural finding that shapes everything: on the agent, **FIM is its own daemon (`wazuh-syscheckd`)** and **Syscollector is a wmodule inside `wazuh-modulesd`** — **separate OS processes** (`src/init/wazuh-client.sh:20`). Under (b) each daemon just links the component and drives its own load/attach/consume loop (the shape FIM already has) — no cross-process transport.

> **Three parts of the issue text assume option (a) and need restating under (b):** (i) parent objective NFR4 ("independent eBPF Module ... shared runtime telemetry provider"), (ii) this issue's title ("standalone runtime telemetry provider"), and (iii) acceptance criterion 5 ("two consumers with distinct filters over one event stream" — no shared stream under (b)). The spike's Scope allowed either shape, so the architecture answer is in scope; the objective/title/criterion wording is the team's to restate. Flagged — see ADR-001 OQ-5. Not silently dropped, not claimed met.

## Deliverables

| # | File | Task | Status |
|---|---|---|---|
| — | `adr/ADR-001-module-boundary.md` | **Boundary decision (a vs b)** | ✅ decided **(b)** by the team (ADR reworked; history kept) |
| — | `adr/ADR-002-min-kernel-per-event-class.md` | Attach strategy + min-kernel per class | ✅ **updated with on-kernel measurements** |
| — | `adr/ADR-003-serialization-and-versioning.md` | Flat event layout + versioning (in-process) | ✅ (IPC-transport parts dropped under (b)) |
| 1 | `01-current-state-audit.md` | Current-state audit + **coupling-extraction map** (C1–C13) | ✅ complete |
| 2 | `02-peer-research.md` | Tetragon / Falco / Inspektor Gadget / Hubble | ✅ complete |
| 3 | `03-event-contract-spec.md` | **Event contract (core deliverable)** | ✅ complete (fields flagged 🅵/🅷 for peer review) |
| 4 | `04-lifecycle-backpressure.md` | Lifecycle, backpressure, degradation | ✅ complete |
| 5 | `05-compatibility-matrix.md` | Distro/kernel compat matrix + caps + MAC | ✅ + **§0 measured update** (see #7) |
| 6 | `poc/` | PoC: single object (LSM+kprobe) loads/attaches/selects/emits w/ full path + correlation keys; exec probe | ✅ **BPF mode measured on 4 kernels** (evidence #7); demonstrates the load/attach/select mechanics that hold under (b) |
| 7 | `06-performance-budget.md` | Event rates, per-event cost, filter placement | ✅ complete |
| 8 | `07-vm-validation-evidence.md` | **On-kernel validation** (6 VMs incl. real Docker container) + `evidence_<vm>.txt` | ✅ complete; viability verdict = viable w/ caveats |

## The one-paragraph story

Today the eBPF engine (`src/syscheckd/src/ebpf/`) is welded to FIM: it takes 9 FIM callbacks via a `fimebpf` singleton, filters using FIM's directory table *inside* the ringbuf callback, enriches uid/gid→name itself, emits the FIM domain type `whodata_evt`, is driven by a FIM thread and FIM's shutdown flag, and only ever produces file-activity events. The extraction generalises it into a **reusable eBPF component (a shared library)** that emits flat, versioned, raw events (file + exec + network) carrying raw correlation keys (`cgroup_id`, mount/pid/net-ns inodes) but **no container knowledge** — with FIM's directory policy and uid/gid enrichment moved out to the consumer. Under the chosen boundary (b), **each module links that library and installs only the hooks it needs** (FIM = file, Syscollector = exec + network), consuming its own in-process stream; there is no central provider and no IPC. The BPF loading mechanism already in-tree (libbpf via `dlopen`, CO-RE, BTF, `BPF_MAP_TYPE_RINGBUF`) is sufficient — **no new external dependency is required**.

## Biggest corrections to prior assumptions (verified)

1. **The numeric `>=5.8` kernel gate is wrong.** RHEL 8.4 backported `BPF_MAP_TYPE_RINGBUF` onto its `4.18-el8` kernel; the numeric gate wrongly excludes a supportable RHEL 8.4+ fleet. Replace it with **runtime capability probes** (ADR-002 D1).
2. **LSM is not the common case.** Stock RHEL / Amazon Linux 2023 don't put `bpf` in `CONFIG_LSM`, so the provider falls back to **kprobes** there. Treat **kprobe as first-class, LSM as an opportunistic upgrade** (ADR-002 D2).
3. **The FIM-specific global event queue must be generalised** (audit C7, lifecycle §3). Under (b) each module owns its own ring buffer + consume loop, so there is no cross-module starvation to solve; the drop-visibility requirement (a dropped event = a missed state) still applies per module.

## Consolidated open questions / coordinate with peers

**Boundary (option (b) — per ADR-001)**
- OQ-1 Ship the load/attach/capability-probe/`_dpath`-`_walk`-fallback logic as **one shared library** both modules link (so two per-module loaders can't diverge). → implementation owners.
- OQ-2 Can both `wazuh-syscheckd` and `wazuh-modulesd` run with `CAP_BPF`+`CAP_PERFMON` only (no `CAP_SYS_ADMIN`) on ≥5.8? → packaging owners.
- OQ-3 Which event classes might two modules both want (the only place (b) duplicates a hook)? Enumerate now. → FIM + IT Hygiene.
- OQ-5 **Three parts of the issue text assume option (a) and need restating under (b):** parent objective NFR4 ("independent eBPF Module ... shared runtime telemetry provider"), the issue title ("standalone runtime telemetry provider"), and acceptance criterion 5 ("two consumers over one event stream"). Architecture answer is in scope; the wording is the team's to restate. → the team.

**Event contract — FIM spike (🅵)**
- OQ-C1 Is `{raw path, inode, dev, mnt_ns}` sufficient for FIM path resolution (raw→logical/host is FIM-owned, out of scope here)? 
- OQ-C4 `RT_EV_FILE_ATTR`: changed-mask vs split sub-reasons.

**Event contract — IT Hygiene / Syscollector spike (🅷, #37533/#37534)**
- OQ-C2 Do process/network inventories want EXEC/CONNECT as realtime events or table-refresh triggers? (**#37534's coverage decision, not ours.**)
- OQ-C3 `args` capture policy (opt-in default, truncation length).

**Kernel / packaging**
- OQ-K1 Per-hook `bpf_d_path` acceptance on el8/el9; `security_inode_setattr` arg layout on `5.14-el9`; RHEL8 `bpf_d_path` backport — **TO BE MEASURED** on VMs (probe commands in `05-`).
- OQ-K2 `bpf_get_current_cgroup_id` == cgroupfs `st_ino` on a live cgroup-v2 host — TBM.
- OQ-K3 SELinux policy module + AppArmor `capability bpf/perfmon` profile the host package must ship (ADR-002 D5).
- OQ-K4 cgroup v1 makes `cgroup_id` ambiguous (`RT_F_CGROUP_V1`) — align the container-correlation key with Container module owners (#37382).

## What was actually executed vs still open
- **Executed on real kernels (see `07-`):** the PoC BPF mode on 4 kernels (6.8, 5.14-el9, 5.10, 4.18-el8) plus a real Docker container — both attach paths (`lsm/file_open`, `kprobe/vfs_open`) load/attach/emit, exec tracepoint, `cgroup_id`==cgroupfs `st_ino` on v2. The userspace core also runs in sim (`./poc_sim --sim`) to show drop-on-full backpressure.
- **Still open:** the two-process concurrent load that (b) actually ships (untested, see `07-` §4 / ADR-001 risk 5); CRI-O; a network-class PoC; measured per-event cost + burst-drop numbers in `06-`; the remaining `[TBM]` cells in `05-` (e.g. `bpf_d_path` acceptance for `path_unlink`/`path_rename`, el9 `security_inode_setattr` layout).
