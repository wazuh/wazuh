# 05 — Kernel / Runtime Compatibility Matrix (Spike #37396, HALF B)

Goal: decide the minimum kernel floor and attach strategy for the **reusable eBPF component each module links** (ADR-001 option (b)) — FIM and Syscollector each load their own hooks — extracted from `src/syscheckd/src/ebpf/`. The kernel facts here are boundary-independent.

Legend: **[V]** = verified with citation · **[I]** = inferred from verified facts · **[TBM]** = to be measured on a real VM (probe command given) · **[Vm]** = measured on-kernel in this spike (see `07-vm-validation-evidence.md`).

## 0. MEASURED UPDATE (on-kernel VM runs) — authoritative; supersedes cells below where noted

Ran the PoC on fresh VMs (`07-vm-validation-evidence.md`). Key corrections to the analysis that follows:

- **[Vm] RHEL-8 (AlmaLinux 8.10, 4.18-el8) is FULLY capable, not "degraded".** `map_type ringbuf is available` (backport **confirmed by measurement**, not inference), BTF present, `bpf_d_path`/`cgroup_id`/`ns`/`ktime_boot` helpers present, `cap_bpf`+`cap_perfmon` present, and **both `lsm/file_open` and `kprobe/vfs_open` attach and emit**. The numeric `≥5.8` gate wrongly excludes it → use runtime capability probes.
- **[Vm] bpf-LSM default state is the OPPOSITE of what the table below assumed.** Measured `/sys/kernel/security/lsm`: **el8, el9, AL2-5.10 all include `bpf` by DEFAULT** (LSM path reachable OOTB); **Ubuntu 24.04 does NOT** (`lockdown,capability,landlock,yama,apparmor`) and needs `lsm=…,bpf` + reboot. So the "Ubuntu 22/24 = best/LSM, RHEL/AL = no LSM" framing is inverted. **Kprobe = portable default; LSM = per-distro-conditional upgrade.**
- **[Vm] 5.10-class kernels require raising `RLIMIT_MEMLOCK`.** AL2 5.10 failed ringbuf map create with `EPERM (memlock 64 KiB)`; `setrlimit(RLIMIT_MEMLOCK, INFINITY)` before load fixes it (mandatory for the 5.10 floor).
- **[Vm] `cgroup_id`==cgroupfs `st_ino` on cgroup v2** proven (ubuntu2404 4302==4302 / 4883==4883, alma9 4829==4829). On v1 (alma8, AL2) `cgroup_id` is ambiguous → use pid/mnt-ns key.
- **[Vm] Container-runtime dimension — real Docker container** (alma9, Docker 29.6.2 over containerd/runc, cgroup driver **systemd**, v2): an event emitted **inside** the container carried `cgroup_id=5351` == the container cgroupfs `st_ino` 5351. The systemd cgroup driver does **not** change `cgroup_id` semantics (only path layout). Docker+containerd covered; **CRI-O not tested** (needs K8s); `cgroupfs` driver not separately tested.
- **[Vm] AL2 *default* kernel is 4.14 (NO BTF/ringbuf/cap_bpf) = EXCLUDED**; AL2 needs the `kernel-5.10` extras package.
- Still **[TBM]**: `bpf_d_path` per-hook acceptance (PoC used manual walk), Ubuntu 20.04/5.4 (unreachable this session), SELinux/AppArmor confinement, network class.

Ground truth from current Wazuh code (given, not re-derived here):
- Engine hard-fails kernels `< 5.8` (`check_invalid_kernel_version` in `ebpf_whodata.cpp`).
- Single 8 MB `BPF_MAP_TYPE_RINGBUF` (`rb`, `1<<23`), CO-RE (`BPF_CORE_READ`, `vmlinux.h`), libbpf via `dlopen` (vendored libbpf-bootstrap).
- One `modern.bpf.o` carries both LSM hooks (`lsm/file_open`, `lsm/path_unlink`, `lsm/path_rename`) and kprobe fallback (`kprobe/vfs_open`, `vfs_unlink`, `vfs_rename`, `security_inode_setattr`). Userspace picks LSM only when `bpf` appears in `/sys/kernel/security/lsm`, else kprobes.
- LSM ships `*_dpath` (uses `bpf_d_path`) and `*_walk` (manual dentry walker); loader prefers dpath, falls back to walk when `bpf_d_path` is rejected for the hook (seen on AL2/AL2023 for `bpf_lsm_path_unlink`).

---

## 1. Feature → minimum MAINLINE kernel (verified)

| Feature | Min mainline | Commit / cite |
|---|---|---|
| BTF (`CONFIG_DEBUG_INFO_BTF`) — enables CO-RE | **4.18** | commit `69b693f0aefa` — [bcc kernel-versions](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md). NOTE: kernel *code* since 4.18, but a distro must actually *build* with `CONFIG_DEBUG_INFO_BTF=y` to emit `/sys/kernel/btf/vmlinux`. |
| `bpf_get_current_cgroup_id` | **4.18** | commit `bf6fa2c893c5` — [torvalds/linux](https://github.com/torvalds/linux/commit/bf6fa2c893c5237b48569a13fa3c673041430b6c), [bcc](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md) |
| BPF trampoline / `fentry`/`fexit` (`BPF_PROG_TYPE_TRACING`) | **5.5** | commit `f1b9509c2fb0` — [bcc](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md) |
| BPF LSM (`BPF_PROG_TYPE_LSM`, KRSI, `CONFIG_BPF_LSM`) | **5.7** | commit `fc611f47f218` — [bcc](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md); [LSM BPF docs](https://docs.kernel.org/bpf/prog_lsm.html) |
| `bpf_get_ns_current_pid_tgid` (ns-scoped pid/tgid) | **5.7** | commit `b4490c5c4e02` — [bcc](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md) |
| `BPF_MAP_TYPE_RINGBUF` | **5.8** | commit `457f44363a88` — [torvalds/linux](https://github.com/torvalds/linux/commit/457f44363a8894135c85b7a9afd2bd8196db24ab), [bcc](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md) |
| `CAP_BPF` + `CAP_PERFMON` (split from `CAP_SYS_ADMIN`) | **5.8** | [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html); [LWN Introduce CAP_BPF](https://lwn.net/Articles/820560/) |
| `bpf_d_path` | **5.10** | commit `6e22ab9da793` — [torvalds/linux](https://github.com/torvalds/linux/commit/6e22ab9da79343532cd3cde39df25e5a5478c692); [LWN](https://lwn.net/Articles/829730/) |
| Sleepable BPF / sleepable LSM (`BPF_F_SLEEPABLE`) | **5.10** | commit `1e6c62a88215` — [bcc](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md) |
| `tracepoint/sched/sched_process_exec` | **~3.4** (very old, stable ABI) | tracepoint predates BPF-tracepoint attach; attachable via BPF since raw-tracepoint era. [I] portable across all target kernels — [Tracee sched_process_exec](https://aquasecurity.github.io/tracee/v0.21/docs/events/builtin/extra/sched_process_exec/) |
| `mnt_idmap` in `vfs_*` / `security_inode_setattr` arg change | **6.3** (idmap), earlier `user_namespace` **5.12** | [I] from code notes; must be handled with `PT_REGS_PARM*_CORE` + per-version CO-RE. **[TBM]** verify exact struct field offsets per target. |

Reading namespace inodes (mnt/pid/net) via `task->nsproxy->*_ns->ns.inum`: available since BTF/CO-RE landed (4.18), but requires reading `struct` fields that shift across versions — treat as CO-RE-guarded, **[I]**.

---

## 2. RHEL / Amazon backport reality (the trap)

RHEL's `4.18 el8` and `5.14 el9` are **not** mainline. Red Hat backports selectively:

- **RHEL 8 BTF**: shipped/enabled from **RHEL 8.2** (`CONFIG_DEBUG_INFO_BTF=y`). **[V]** [tracee #713](https://github.com/aquasecurity/tracee/discussions/713), [Pulsar kernel-reqs](https://pulsar.sh/docs/faq/kernel-requirements/).
- **RHEL 8 ring buffer**: `BPF_MAP_TYPE_RINGBUF` **backported to RHEL 8.4** (into the 4.18 el8 kernel). **[V]** [bcc](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md) distro note. So RHEL 8.4+ satisfies the ringbuf requirement despite reporting "4.18".
- **RHEL BPF LSM**: `BPF_PROG_TYPE_LSM` present in RHEL family **>= 8.5** kernels. **[V]** [Pulsar kernel-reqs](https://pulsar.sh/docs/faq/kernel-requirements/). BUT: RHEL default `CONFIG_LSM="yama,integrity,selinux"` — **`bpf` is NOT in the active LSM list by default**. **[V]** [linux-security-module list](https://www.spinics.net/lists/linux-security-module/msg40357.html). => `/sys/kernel/security/lsm` will not contain `bpf`, so our loader **falls back to kprobes on stock RHEL** even though the program type exists.
- **Amazon Linux 2** (kernel 5.10 via Extras): BTF present from `5.10.155-138.670.amzn2`; older 5.10 builds have partial/missing BTF. **[V]** [Pulsar kernel-reqs](https://pulsar.sh/docs/faq/kernel-requirements/), [AWS re:Post](https://repost.aws/questions/QUKllk06xLSBGQXBowwkSP_Q/amazon-linux-2-kernel-5-10-xxx-btf-info-kernel-config).
- **Amazon Linux 2023** (6.1): BTF yes; default LSMs include `lockdown` + `yama` — **`bpf` not in default LSM list** => kprobe fallback in practice. `kernel.unprivileged_bpf_disabled` set. **[V]** [AL2023 kernel-hardening](https://docs.aws.amazon.com/linux/al2023/ug/kernel-hardening.html). Code already special-cases AL2/AL2023 for `bpf_lsm_path_unlink` `bpf_d_path` rejection → `*_walk`.

> **Consequence**: BPF-LSM attach is realistically reachable only where `bpf` is in `CONFIG_LSM` AND on the boot cmdline `lsm=`. Among the target set that is **Ubuntu 22.04/24.04 (bpf enabled by default in CONFIG_LSM)** and custom-configured hosts. Everywhere else the provider runs the **kprobe path**. Design the provider so kprobe is the *primary* supported path and LSM is an opportunistic upgrade.

---

## 3. Compatibility matrix (target floors)

Columns: LSM attach reachable? / kprobe+tracepoint attach? / RINGBUF? / `bpf_d_path`? / `bpf_get_current_cgroup_id`? / file ev / exec ev / net ev / perf category / notes.

| Distro (kernel) | BPF-LSM reachable | kprobe+tp | RINGBUF | bpf_d_path | cgroup_id | file | exec | net | Perf cat | Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| **RHEL 8** (4.18 el8; tested 8.10) | **Yes (bpf in default LSM list)** [Vm] | Yes [Vm] | **Yes (backport confirmed by measurement)** [Vm] | helper present [Vm]; per-hook accept **[TBM]** | Yes [Vm] | **LSM+kprobe both attach+emit** [Vm] | tp/sched_process_exec **works** [Vm] | kprobe tcp_connect [I] | **good (was mislabeled "degraded")** | AlmaLinux 8.10 4.18.0-553: ringbuf+BTF+cap_bpf/perfmon all present; both paths emit. Current 5.8 gate REJECTS this fully-working kernel → use capability probes. cgroup **v1** (id ambiguous). |
| **Ubuntu 20.04** (5.4) | No (LSM is 5.7) [V] | Yes [I] | **No** (ringbuf is 5.8) [V] | No (5.10) [V] | Yes [V] | kprobe only, **no ringbuf** → needs perfbuf fallback | tp [I] | kprobe [I] | **excluded / degraded** | 5.4 < 5.8: current engine rejects. Also stock 20.04 had `CONFIG_DEBUG_INFO_BTF` **not set** on early 5.4 → CO-RE broken. **[V]** [tracee #713] |
| **Debian 11** (5.10) | No (bpf not default in CONFIG_LSM) [I][TBM] | Yes [I] | Yes (5.8) [V] | **Yes (5.10)** [V] | Yes [V] | kprobe + dpath | tp [I] | kprobe [I] | **good** | BTF enabled on amd64/arm64. **[V]** [tracee #713] |
| **RHEL 9** (5.14 el9; tested AlmaLinux 9.7) | **Yes — bpf in default LSM list** [Vm] (was assumed "No by default") | Yes [Vm] | Yes [Vm] | helper present [Vm] | Yes [Vm] | **LSM+kprobe both attach+emit** [Vm] | tp **works** [Vm] | kprobe/fexit [I] | **best** | AlmaLinux 9.7 5.14.0-611: LSM active OOTB (`…,selinux,bpf`); cgroup **v2**, `cgroup_id`==`st_ino` (4829==4829) [Vm]; libbpf-devel via CRB repo. `security_inode_setattr` el9 arg layout still **[TBM]** (PoC didn't exercise setattr). |
| **Ubuntu 22.04** (5.15) | **doubtful** — prior "Yes" claim contradicted by 24.04 measurement; **[TBM]** re-check | Yes [I] | Yes [V] | Yes [V] | Yes [V] | kprobe default; LSM only if `bpf` in active list | tp [I] | LSM socket / kprobe [I] | good | Prior source claimed bpf in default CONFIG_LSM, but **measured 24.04 does NOT** ship it active → 22.04 needs re-verification (`cat /sys/kernel/security/lsm`). |
| **Ubuntu 24.04** (6.8) | **No by default** [Vm] (`lockdown,capability,landlock,yama,apparmor`) — needs `lsm=…,bpf`+reboot | Yes [Vm] | Yes [Vm] | helper present [Vm] | Yes [Vm] | **kprobe attaches+emits [Vm]; LSM attaches+emits after enabling bpf-LSM [Vm]** | tp **works** [Vm] | LSM socket [I] | good (LSM opt-in) | cgroup **v2**, `cgroup_id`==`st_ino` (4302==4302) [Vm]. Strict verifier note stands. AppArmor userns/bpf mediation ON (see §5). |
| **Amazon Linux 2** (5.10 Extras) | No (bpf not default) [I] | Yes [I] | Yes (5.8) [V] | Yes on file_open; **rejected for path_unlink** → `*_walk` [V-code] | Yes [V] | kprobe/`*_walk` | tp [I] | kprobe [I] | **good** | Require BTF build `>= 5.10.155-138.670.amzn2`. **[V]** [AWS re:Post] |
| **Amazon Linux 2023** (6.1) | No default (lockdown+yama) [V] | Yes [I] | Yes [V] | Yes / `*_walk` fallback [V-code] | Yes [V] | kprobe/`*_walk` | tp [I] | kprobe [I] | **good** | `unprivileged_bpf_disabled` set. [V] [AL2023 hardening] |

`file`/`exec`/`net` cells state the *actual runtime path chosen*, not just theoretical capability.

---

## 4. Attach strategy DECISION per event class

### File events (open/create/write/unlink/rename/setattr) — the FIM core
- **Modern + LSM reachable (Ubuntu 22.04/24.04, custom `lsm=...,bpf`)**: `lsm/file_open`, `lsm/path_unlink`, `lsm/path_rename` with `bpf_d_path`. Cleanest path resolution, hook fires at the security decision point. Fall back to `*_walk` where `bpf_d_path` rejected. **[V]** capability, **[I]** best-choice.
- **Everywhere else (the majority: RHEL 8/9, Debian 11, AL2/AL2023, Ubuntu 20.04)**: **kprobe** on `vfs_open`/`vfs_unlink`/`vfs_rename`/`security_inode_setattr`. This is the realistic primary path. Requires per-version CO-RE guards for `renamedata` (5.12), `mnt_idmap` (6.3), `security_inode_setattr` arg change (6.0). Use `PT_REGS_PARM*_CORE`.
- **Recommendation**: Treat **kprobe as the baseline/first-class** path; LSM as an opportunistic quality upgrade auto-selected via `/sys/kernel/security/lsm`. Do NOT require LSM.

### Process-exec events — Syscollector's main new interest
- **Single portable path for ALL targets**: `tracepoint/sched/sched_process_exec` (stable ABI, present since 3.x, portable, CO-RE-friendly). **[V]** [Tracee](https://aquasecurity.github.io/tracee/v0.21/docs/events/builtin/extra/sched_process_exec/). Avoid `kprobe/sys_execve` (arch/syscall-wrapper churn) and `tracepoint/syscalls/sys_enter_execve` (noted unreliable). **Recommendation: tracepoint/sched_process_exec on every kernel.** No LSM/kprobe variant needed.
- Complement with `sched_process_exit` for lifecycle if consumers need it.

### Network events (connect/accept) — future consumer
- **Baseline portable**: `kprobe/fexit` on `tcp_connect` / `inet_csk_accept` (also `tcp_v4_connect`/`tcp_v6_connect`). `fexit` needs BTF trampoline (5.5+), so on RHEL8 use plain kprobe. **[I]**
- **LSM-capable hosts**: `lsm/socket_connect`, `lsm/socket_accept` for decision-point capture. **[I]**
- Cgroup/sockops (`cgroup/connect4/6`) is an alternative but is cgroup-v2-attach-scoped, not a general host telemetry source. **[I]**
- **Recommendation**: kprobe/fexit on TCP connect/accept as baseline; LSM socket hooks opportunistically. Mark **[TBM]** — network is out of current code scope; needs a spike POC.

---

## 5. Host-process capability & LSM/AppArmor delta

### Capabilities (systemd host unit)
| Kernel | Minimum caps to load+attach our programs |
|---|---|
| **< 5.8** (RHEL8 4.18, Ubuntu 20.04 5.4) | **`CAP_SYS_ADMIN`** — CAP_BPF/CAP_PERFMON do not exist yet. **[V]** [LWN 820560](https://lwn.net/Articles/820560/) |
| **>= 5.8** | `CAP_BPF` + `CAP_PERFMON` (kprobe/tracepoint/perf programs need PERFMON) + `CAP_DAC_READ_SEARCH` (read `/sys/kernel/btf/vmlinux` and resolve paths). LSM-type programs additionally effectively need admin-equivalent; `CAP_BPF` alone can't load tracing/kprobe types. **[V]** [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) |

**Delta / recommendation**: ship the unit with `AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_DAC_READ_SEARCH` on 5.8+, and detect-and-fallback to `CAP_SYS_ADMIN` on older. Simplest cross-version answer for a monitoring agent: run with `CAP_SYS_ADMIN` (superset, works everywhere) but document the least-privilege 5.8+ set for hardened deployments. Reading paths / dentry walk and `bpf_probe_read` of kernel memory need `CAP_PERFMON` — pure `CAP_BPF` is insufficient for our kprobe path.

### SELinux (RHEL / AL2023)
- SELinux has a `bpf` capability class; a confined domain needs `allow <domain> self:bpf { map_create map_read map_write prog_load prog_run };` and `capability2 { bpf perfmon }`. The Wazuh agent policy must ship these or run in an unconfined/permissive domain. **[TBM]** — write a targeted `.te` and test with `ausearch -m avc` on RHEL 9 enforcing.

### AppArmor (Ubuntu)
- **Ubuntu 23.10+ / 24.04**: `kernel.apparmor_restrict_unprivileged_userns=1` and AppArmor mediates `bpf()` for confined profiles. **[V]** [Ubuntu 24.04 release notes](https://documentation.ubuntu.com/release-notes/24.04/), [Ubuntu security / apparmor](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/), [LP #2046477](https://bugs.launchpad.net/bugs/2046477). If the Wazuh agent ships/gets a confined AppArmor profile, that profile must include `capability bpf,` / `capability perfmon,` and appropriate `bpf` rules; otherwise attach fails on 24.04. A privileged (root, unconfined) systemd service is unaffected, but document this for hardened hosts.

---

## 6. cgroup id correlation (consumer key)

- `bpf_get_current_cgroup_id()` returns the **kernfs inode id of the cgroup-v2 directory** of the current task. **[V]** [ebpf.io helper](https://docs.ebpf.io/linux/helper-function/bpf_get_current_cgroup_id/), commit `bf6fa2c893c5`.
- Userspace obtains the same 64-bit id for a path via the **`name_to_handle_at()` / `f_handle` API** on the cgroup-v2 path (the low 8 bytes of the file handle = cgroup id). It equals `stat().st_ino` of the cgroupfs dir **only under cgroup v2 unified**. **[V]** helper docs.
- **cgroup v1**: multiple hierarchies → "the" cgroup id is ambiguous; the helper's meaning is not well-defined across controllers. Do not rely on it for correlation on v1 hosts. **[I]**
- **systemd vs cgroupfs driver**: does not change the id semantics (both create v2 dirs with kernfs inodes); it only changes the *path layout* (`/system.slice/...` vs custom). Correlation still works as long as consumer resolves the id from the same v2 mount. **[I]**
- **Implication for FIM+Syscollector**: emit the raw 64-bit cgroup-v2 id as the correlation key, plus resolve it once in userspace to the cgroup path for human-readable context. Gate this on "is cgroup v2 unified" (`stat -f /sys/fs/cgroup` type `cgroup2fs` / `0x63677270`). On v1-only hosts, mark cgroup id **untrusted** and fall back to pid-namespace inode as the container key. **[TBM]** verify id==st_ino equality on a v2 host.

---

## 7. Min-kernel DECISION RECORD

**Options considered**

- **A. Keep 5.8 floor (status quo).** Clean ringbuf everywhere; loses RHEL 8 entirely (Wazuh Tier-1). Unacceptable for Syscollector which must cover the RHEL 8 fleet.
- **B. Lowest common denominator 4.18/5.4.** Must add a **perf-buffer fallback** for <5.8 (no ringbuf) and CO-RE guards down to 4.18. High complexity, and Ubuntu 20.04 stock 5.4 has BTF disabled on early builds (CO-RE broken) → still excluded in practice.
- **C. (RECOMMENDED) Split floor by event class + a hard BTF requirement.**

**Recommendation C — decision:**

1. **Hard requirement: working CO-RE, i.e. `/sys/kernel/btf/vmlinux` present.** Refuse to load without it (clear log). This is the real gate, not a version number.
2. **File events (FIM)**: floor = **ringbuf-capable kernel**. That is mainline **5.8+** OR **RHEL 8.4+ (backported ringbuf)** OR **AL2 5.10+ with BTF**. Primary path = **kprobe**; LSM auto-upgrade where `bpf` in `/sys/kernel/security/lsm`. Do NOT keep the current numeric `>=5.8` check — replace with a **runtime capability probe** (ringbuf map create + BTF present) so RHEL 8.4's "4.18" passes.
3. **Exec events (Syscollector)**: floor = **any BTF-enabled kernel** via `tracepoint/sched_process_exec`. Effectively RHEL 8.2+, Debian 11, AL2 (BTF build), all Ubuntu. Cheapest, most portable class.
4. **Network events**: defer; kprobe/fexit baseline, LSM opportunistic. **[TBM]** POC required.
5. **Below floor (Ubuntu 20.04 5.4 / no-BTF)**: **documented exclusion**. Do not build a perf-buffer path unless product explicitly requires 20.04 eBPF telemetry — the maintenance cost (dual transport + 4.x CO-RE) is not justified; 20.04 goes EOL 2025 anyway.

Rationale: the *actual* portability boundary is **BTF availability + ringbuf availability**, both probeable at runtime, not the kernel version string. Replacing the numeric gate with capability probes gains the entire RHEL 8.4+ fleet (huge for Wazuh) at near-zero code cost, while a genuine <5.8 perf-buffer path is expensive and covers only shrinking EOL distros.

---

## 8. Probe commands for [TBM] cells (run on real VMs)

```bash
# 1. LSM active list — decides LSM vs kprobe path
cat /sys/kernel/security/lsm            # look for ",bpf,"

# 2. BTF present? (hard requirement for CO-RE)
ls -l /sys/kernel/btf/vmlinux
bpftool btf dump file /sys/kernel/btf/vmlinux format c | head

# 3. Full feature probe: ringbuf, LSM prog type, d_path, helpers
bpftool feature probe kernel 2>/dev/null | grep -Ei 'ringbuf|lsm|d_path|cgroup_id|ns_current_pid'
bpftool feature probe | grep 'map_type ringbuf'
bpftool feature probe | grep 'program_type lsm'

# 4. cgroup version (correlation key validity)
stat -fc %T /sys/fs/cgroup            # cgroup2fs == unified v2
mount | grep cgroup

# 5. Can we actually ATTACH lsm/file_open here? (minimal test)
#    build test.bpf.c with SEC("lsm/file_open") + a ringbuf, load via libbpf,
#    check bpf_object__load() and bpf_program__attach() return, then verify
#    bpf_d_path acceptance per hook (expect rejection on AL2 path_unlink).

# 6. Capabilities available to the (systemd) service
grep Cap /proc/self/status; capsh --decode=<CapEff>

# 7. Kernel config (when /proc/config.gz or /boot/config-$(uname -r) exists)
zgrep -E 'BPF_LSM|DEBUG_INFO_BTF|CONFIG_LSM=' /boot/config-$(uname -r)

# 8. RHEL/AL: confirm ringbuf backport on the exact minor
bpftool feature probe | grep ringbuf   # on RHEL 8.4 4.18 el8 -> expect available
```

Cells marked [TBM] above (per-hook `bpf_d_path` acceptance on el8/el9, `security_inode_setattr` arg layout on el9, cgroup id==st_ino equality, SELinux/AppArmor confinement) must be filled from these probes on actual RHEL 8/9, AL2/AL2023, and Ubuntu 22.04/24.04 VMs before finalizing.

---

## Sources
- [iovisor/bcc — BPF Features by Kernel Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
- [torvalds/linux 457f44363a88 — BPF ring buffer](https://github.com/torvalds/linux/commit/457f44363a8894135c85b7a9afd2bd8196db24ab)
- [torvalds/linux 6e22ab9da793 — bpf_d_path](https://github.com/torvalds/linux/commit/6e22ab9da79343532cd3cde39df25e5a5478c692)
- [torvalds/linux bf6fa2c893c5 — bpf_get_current_cgroup_id](https://github.com/torvalds/linux/commit/bf6fa2c893c5237b48569a13fa3c673041430b6c)
- [LWN — Introduce CAP_BPF](https://lwn.net/Articles/820560/) · [LWN — CAP_PERFMON](https://lwn.net/Articles/812719/)
- [capabilities(7) man page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [LSM BPF Programs — kernel.org](https://docs.kernel.org/bpf/prog_lsm.html)
- [tracee #713 — Distro versions and BTF support](https://github.com/aquasecurity/tracee/discussions/713)
- [Pulsar — Kernel Requirements](https://pulsar.sh/docs/faq/kernel-requirements/)
- [Ubuntu 24.04 release notes](https://documentation.ubuntu.com/release-notes/24.04/) · [Ubuntu AppArmor security docs](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/) · [LP #2046477](https://bugs.launchpad.net/bugs/2046477)
- [Ubuntu 22.04 security — bpf in CONFIG_LSM](https://ubuntu.com/blog/whats-new-in-security-for-ubuntu-22-04-lts)
- [AL2023 kernel hardening](https://docs.aws.amazon.com/linux/al2023/ug/kernel-hardening.html) · [AWS re:Post — AL2 5.10 BTF](https://repost.aws/questions/QUKllk06xLSBGQXBowwkSP_Q/amazon-linux-2-kernel-5-10-xxx-btf-info-kernel-config)
- [ebpf.io — bpf_get_current_cgroup_id](https://docs.ebpf.io/linux/helper-function/bpf_get_current_cgroup_id/)
- [Tracee — sched_process_exec](https://aquasecurity.github.io/tracee/v0.21/docs/events/builtin/extra/sched_process_exec/)
- [linux-security-module list — RHEL CONFIG_LSM default](https://www.spinics.net/lists/linux-security-module/msg40357.html)
