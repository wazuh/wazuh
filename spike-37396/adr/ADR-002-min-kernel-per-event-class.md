# ADR-002 — Attach strategy & minimum kernel, per event class

**Status:** Proposed (spike #37396) — **updated with on-kernel measurements (`07-vm-validation-evidence.md`).** **Needs review by:** FIM spike, IT Hygiene spike, agent-packaging owners.

> **MEASURED UPDATE (supersedes assumptions below):**
> - **D1 is now measured-true:** RHEL-8 (AlmaLinux 8.10, 4.18-el8) has ringbuf backported and runs both attach paths — the numeric ≥5.8 gate wrongly excludes it. Confirmed on-kernel, not inferred.
> - **The bullet "BPF-LSM not reachable on stock RHEL/Amazon; LSM only on Ubuntu 22/24" is WRONG (measured).** Reality: `/sys/kernel/security/lsm` includes `bpf` **by default on el8, el9, and AL2-5.10**; **Ubuntu 24.04 does NOT** (needs `lsm=…,bpf`+reboot). Kprobe stays the portable default, but **LSM is default-on for RHEL-family/AL2-5.10 and opt-in on Ubuntu** — the opposite of the original framing.
> - **New hard requirement:** raise `RLIMIT_MEMLOCK` before load on 5.10-class kernels (AL2 5.10 ringbuf create fails with EPERM otherwise).
> - **AL2 default kernel is 4.14 → excluded (no BTF/ringbuf);** AL2 needs the 5.10 extras kernel.

## Context

The current engine gates on a **numeric** kernel floor: `major<5 || (major==5 && minor<8)` (`ebpf_whodata.cpp:333`). Verified kernel research (`05-compatibility-matrix.md`) shows this is both too strict and misleading:

- **RINGBUF, CO-RE/BTF and BPF-LSM were backported into distro kernels whose numeric version is far below the mainline landing version.** Notably RHEL 8.4 ships `BPF_MAP_TYPE_RINGBUF` on a `4.18-el8` kernel; RHEL 8.2 has BTF. A numeric `>=5.8` gate **wrongly excludes a supportable RHEL 8.4+ fleet**.
- ~~**BPF-LSM is not reachable on stock RHEL / Amazon Linux 2023** … LSM realistically only on Ubuntu 22.04/24.04.~~ **← RETRACTED by measurement.** Measured default `/sys/kernel/security/lsm`: el8/el9/AL2-5.10 **include `bpf`**; Ubuntu 24.04 **does not**. `bpf_get_current_cgroup_id`, `bpf_d_path`, ringbuf, BTF, `cap_bpf`/`cap_perfmon` all present on 4.18-el8 through 6.8. **Kprobe is the portable default; LSM is default-on for RHEL-family/AL2-5.10 and opt-in (cmdline) on Ubuntu.** (See `07-vm-validation-evidence.md` F2.)

Verified feature-landing (mainline; see compat doc for citations — sourced from bcc kernel-versions + torvalds commits):

| Feature | Mainline | Notes |
|---|---|---|
| BTF (`CONFIG_DEBUG_INFO_BTF`) | 4.18 | distro must enable it; Ubuntu 20.04 early kernels shipped it off |
| `bpf_get_current_cgroup_id` | 4.18 | v2 kernfs inode id |
| fentry/fexit | 5.5 | BTF-based |
| BPF-LSM (KRSI) | 5.7 | needs `bpf` in `CONFIG_LSM`/`lsm=` |
| `bpf_get_ns_current_pid_tgid` | 5.7 | ns-scoped pid |
| `BPF_MAP_TYPE_RINGBUF`, `CAP_BPF`/`CAP_PERFMON` | 5.8 | RHEL 8.4 backported ringbuf to 4.18-el8 |
| `bpf_d_path`, sleepable hooks | 5.10 | per-hook allowlist varies (AL2/AL2023 reject some) |
| `bpf_ktime_get_boot_ns` | 5.7 | else fall back to `bpf_ktime_get_ns` |

## Decision

### D1 — Replace the numeric gate with **runtime capability probes**
Gate on *capabilities actually present*, not on a version number:
1. Can we create a `BPF_MAP_TYPE_RINGBUF` map? (probe map-create)
2. Is BTF present (`/sys/kernel/btf/vmlinux`) for CO-RE?
3. Is `bpf` in `/sys/kernel/security/lsm`? (LSM upgrade eligibility)
4. Does `bpf_d_path` load for the target hook? (already handled via `_dpath`/`_walk` retry)

This admits RHEL 8.4+ and Amazon Linux 2 (5.10) that the numeric gate rejects, and cleanly excludes kernels that merely *claim* a version but lack the backport.

### D2 — Attach strategy per event class

| Event class | Primary (modern) | Fallback (portable) | Floor |
|---|---|---|---|
| **File** (open/unlink/rename/attr) | LSM hooks (`lsm/file_open`,`path_unlink`,`path_rename`) **only where `bpf` is in active LSM list** — namespace-correct paths via `bpf_d_path` | **kprobes** (`vfs_open`/`vfs_unlink`/`vfs_rename`/`security_inode_setattr`) — the realistic default on RHEL/Amazon | **ringbuf-capable**: mainline ≥5.8, **RHEL 8.4+ (4.18-el8)**, AL2 (5.10) |
| **Process exec** | `tracepoint/sched_process_exec` — most portable, stable ABI | (same tracepoint everywhere) | any **BTF** kernel (≥4.18 with BTF on) |
| **Process exit** | `tracepoint/sched_process_exit` | — | same as exec |
| **Network** (connect/accept/bind) | fentry/fexit on `tcp_connect`/`inet_csk_accept` (≥5.5) | kprobe on same + `__sys_bind` | kprobe baseline; **network deferred to a later phase** |

Rationale: exec via tracepoint is the single most portable source and should be the reference implementation for the new classes. LSM stays as an *upgrade* (better paths) not a requirement.

### D3 — Minimum-kernel decision (lowest-common-denominator with documented exclusions)

- **Supported floor = "ringbuf-capable + BTF"**: mainline ≥5.8, RHEL 8.4+, RHEL 9, Debian 11 (5.10), Ubuntu 22.04 (5.15), Ubuntu 24.04 (6.8), Amazon Linux 2 (5.10) & 2023 (6.1).
- **Documented exclusion: Ubuntu 20.04 (5.4)** — no `BPF_MAP_TYPE_RINGBUF` (5.8) and early images shipped BTF off. The provider PROBE fails cleanly → DISABLED → FIM falls back to the audit provider (no regression vs a world without eBPF). Document this in release notes.
- Degraded-feature note: on kprobe-only hosts, paths come from the manual dentry walker (`get_path_str_from_path`), which is less namespace-aware than `bpf_d_path`. Acceptable; FIM already consumes these.

### D4 — Host-process capabilities (systemd package, not a pod)

| Kernel | Required capabilities |
|---|---|
| < 5.8 (kprobe on backported ringbuf, e.g. some el8) | `CAP_SYS_ADMIN` (+ `CAP_DAC_READ_SEARCH`) — `CAP_BPF` did not exist |
| ≥ 5.8 | `CAP_BPF` **+** `CAP_PERFMON` **+** `CAP_DAC_READ_SEARCH` (CAP_BPF alone is insufficient for kprobe/tracing-program loads) |

Under the chosen boundary (ADR-001 option (b)) each module that loads BPF holds exactly these: `wazuh-syscheckd` (FIM) and `wazuh-modulesd` (Syscollector). Their systemd units set `AmbientCapabilities=`/`CapabilityBoundingSet=` accordingly (scoped to `CAP_BPF`+`CAP_PERFMON`+`CAP_DAC_READ_SEARCH`, not full `CAP_SYS_ADMIN`, on ≥5.8). Any agent process that does not load BPF stays unprivileged. (This is ADR-001 risk 1: privilege in two daemons rather than one, an accepted trade-off.)

### D5 — LSM / MAC policy delta a host package must ship or document
- **SELinux (RHEL)**: the provider domain needs the `bpf` capability class (`allow <domain> self:bpf { map_create map_read map_write prog_load prog_run };`) and `sys_admin`/`perfmon` capability as applicable. Ship a policy module or document the booleans.
- **AppArmor (Ubuntu 23.10+/24.04, VERIFIED)**: these releases **mediate `bpf()`** and restrict unprivileged user namespaces by default. A confined agent profile must declare `capability bpf,` and `capability perfmon,`. Document for confined installs.

## Consequences
- Broader real-world coverage (RHEL 8.4+ admitted) with an honest, single documented exclusion (20.04).
- The kprobe path becomes the tested default rather than a fallback afterthought — CI must exercise it first.
- New exec/network programs inherit the per-kernel arg-layout discipline already in `modern.bpf.c` (see audit §7).

## To-be-measured (carried from compat doc; run on real VMs)
- Per-hook `bpf_d_path` acceptance on el8/el9.
- `security_inode_setattr` / `mnt_idmap` arg layout on RHEL 9's `5.14-el9`.
- Whether RHEL 8 backported `bpf_d_path` (assumed **no** → `_walk` on el8).
- `bpf_get_current_cgroup_id` == cgroupfs `st_ino` equality on a live v2 host.
- Probe commands for each are in `05-compatibility-matrix.md`.
