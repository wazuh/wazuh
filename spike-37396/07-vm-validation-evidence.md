# 07 — On-kernel VM validation evidence (spike #37396)

Empirical backbone that was missing from the design half. Every claim here is **measured on a real kernel** in this session unless marked otherwise. Raw captures are in `evidence_<vm>.txt` next to this file. Legend: **[V]** measured here (output pasted/cited) · **[UNREACHABLE]** could not run in available infra.

## 0. Infra & method (honest constraints)

- The host's **pre-existing** Vagrant VMs were created by **UID 0**; VirtualBox refuses to let this user (UID 1000) manage them (`vagrant --prune` errors with exactly that). So all tests run on **fresh VMs I own**, booted from locally-cached boxes.
- WSL2 cannot reach VirtualBox's NAT forward (bound to Windows `127.0.0.1`, a different network namespace). Worked around by rebinding each VM's ssh forward to `0.0.0.0` via `VBoxManage.exe controlvm … natpf1` and connecting to the Windows-host gateway IP. Harness: `spike37396-vms/run_vm.sh` (+ `run_probes.sh`, `enable_bpf_lsm.sh`).
- Each VM: installed clang/llvm/libbpf-dev(el)/bpftool/make/gcc, generated `vmlinux.h` from the running kernel's BTF, compiled the PoC (`file_open.bpf.o` with `lsm/file_open`+`kprobe/vfs_open`, plus `exec_probe` = `tracepoint/sched_process_exec`), loaded both attach paths, created files, and captured events + per-consumer delivery/drop stats + the `cgroup_id`↔`st_ino` comparison.

## 1. Results matrix (all [V] measured here)

| VM / kernel | LSM `bpf` active (default) | BTF | ringbuf | `lsm/file_open` attach+emit | `kprobe/vfs_open` attach+emit | exec tracepoint | cgroup | `cgroup_id`==`st_ino` | caps present |
|---|---|---|---|---|---|---|---|---|---|
| **ubuntu2404** — 6.8.0-86 | **NO** (`…,yama,apparmor`) → added via `lsm=` cmdline | yes | yes | **yes** (produced=5) after enabling bpf-LSM | **yes** (produced=5) | **yes** | v2 | **yes (4302==4302, 4883==4883)** | bpf,perfmon,sys_admin,dac_read |
| **alma9** — 5.14.0-611 el9_7 | **YES** (`…,selinux,bpf`) | yes | yes | **yes** (produced=5) | **yes** (produced=5) | **yes** | v2 | **yes (4829==4829)** | bpf,perfmon,sys_admin,dac_read |
| **alma8** — 4.18.0-553 el8_10 | **YES** (`…,selinux,bpf`) | yes | **yes (BACKPORTED)** | **yes** (produced=5) | **yes** (produced=5) | **yes** | v1 | n/a (v1) | bpf,perfmon,sys_admin,dac_read |
| **amazonlinux2 (extras 5.10)** — 5.10.260 | **YES** (`…,selinux,bpf`) | yes | yes | **yes** (produced=5)¹ | **yes** (produced=5)¹ | (built) | v1 | n/a (v1) | bpf,perfmon,sys_admin,dac_read |
| **amazonlinux2 (default 4.14)** — 4.14.336 | no | **NO** | **NO** | n/a | n/a | n/a | v1 | n/a | only sys_admin,dac_read (no bpf/perfmon) → **EXCLUDED** |
| **ubuntu2004** — 5.4 | — | — | — | — | — | — | — | — | [UNREACHABLE] this session² |

¹ AL2 5.10 required raising `RLIMIT_MEMLOCK` first (see §3). ² ubuntu2004 booted but its ssh was unreachable over the WSL→VBox NAT after a port-forward race; the 5.4 exclusion rests on the documented ringbuf floor (5.8) — not newly measured here.

## 2. Headline findings (these correct the design)

### F1 — The numeric `≥5.8` kernel gate is wrong; RHEL-8 4.18 is fully capable [V]
On **AlmaLinux 8.10 / kernel 4.18.0-553 el8_10** (`evidence_alma8.txt`):
```
eBPF map_type ringbuf is available
  YES bpf_d_path / bpf_get_current_cgroup_id / bpf_get_ns_current_pid_tgid / bpf_ktime_get_boot_ns
attach strategy: lsm/file_open   → produced: 5, syscollector delivered=5
attach strategy: kprobe/vfs_open → produced: 5, syscollector delivered=5
EXEC pid=21094 … comm=echo   (tracepoint/sched_process_exec)
caps: cap_bpf, cap_perfmon, cap_sys_admin, cap_dac_read_search
```
**The RHEL-8 ring-buffer backport onto 4.18-el8 is confirmed by direct measurement** (was secondary-source-only in ADR-002). CO-RE/BTF, both attach paths, exec, and the 5.8-era caps (`cap_bpf`/`cap_perfmon`) are all present. A numeric `≥5.8` gate would **wrongly exclude a fully-working RHEL-8.10 fleet** → confirms ADR-002's move to **runtime capability probes**.

### F2 — bpf-LSM default state is the OPPOSITE of the earlier assumption [V]
| Distro | `/sys/kernel/security/lsm` (default) | LSM path reachable OOTB? |
|---|---|---|
| AlmaLinux 8.10 (el8) | `capability,yama,selinux,bpf` | **YES** |
| AlmaLinux 9.7 (el9) | `lockdown,capability,landlock,yama,selinux,bpf` | **YES** |
| Amazon Linux 2 (5.10) | `capability,lockdown,yama,selinux,bpf` | **YES** |
| **Ubuntu 24.04 (6.8)** | `lockdown,capability,landlock,yama,apparmor` | **NO** (needs `lsm=…,bpf` + reboot) |

ADR-002 assumed "RHEL/AL default `CONFIG_LSM` lacks bpf; LSM realistically only on Ubuntu 22/24". **Measurement flips this**: RHEL-family and AL2-5.10 ship `bpf` in the active LSM list by default; **Ubuntu 24.04 does not**. Enabling it on Ubuntu (`lsm=lockdown,capability,landlock,yama,apparmor,bpf` + reboot) then makes `lsm/file_open` attach and emit (produced=5, `evidence_ubuntu2404.txt`). Conclusion stands but for the opposite reason: **kprobe must be the portable default; LSM is a per-distro-conditional upgrade** (available by default on el8/el9/AL2-5.10, opt-in on Ubuntu).

### F3 — 5.10-class kernels need `RLIMIT_MEMLOCK` raised (real portability requirement) [V]
On AL2 5.10 the first PoC run failed:
```
libbpf: map 'rb': failed to create: Operation not permitted(-1)
libbpf: permission error while running as root; try raising 'ulimit -l'? current value: 64.0 KiB
```
Pre-5.11 kernels (incl. AL2's 5.10 backport) charge BPF maps against `RLIMIT_MEMLOCK` (default 64 KiB) instead of memcg, so an 8 MiB ring buffer fails to create even as root. **Fix (mandatory for the 5.10 floor):** `setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)` before load. After the fix, both paths attach+emit (produced=5). The extraction design/loader must do this; added to the PoC (`dispatcher.c`, `exec_probe.c`).

### F4 — `cgroup_id` (in-kernel) == cgroupfs `st_ino` on cgroup v2 [V]
The correlation-key equality the whole consumer-side container join depends on, matched exactly on two independent v2 hosts:
- ubuntu2404: exec `cgroup_id=4302` == `stat -c %i /sys/fs/cgroup/spike37396.test = 4302` (also `4883==4883` in a prior run).
- alma9: `cgroup_id=4829` == `4829`.
On **cgroup v1** hosts (alma8, AL2) `bpf_get_current_cgroup_id` returns an ambiguous value (observed `1`); the equality is correctly skipped — matches the `RT_F_CGROUP_V1` design note (consumers must fall back to a pid/mnt-ns key on v1).

### F5 — the single `.o` / dual-path / userspace-autoload model works on every capable kernel [V]
Every reachable capable kernel loaded the SAME `file_open.bpf.o` containing both `lsm/file_open` and `kprobe/vfs_open`, and the userspace loader selected one via `/sys/kernel/security/lsm` (mirroring the real engine's `select_programs()`), attached it, and emitted real events to the consumer. This load/attach/select mechanic is what boundary (b) relies on per module (each module runs it for its own hooks) — **empirically confirmed on 6.8, 5.14-el9, 5.10, and 4.18-el8**. Not yet exercised: two such loads running concurrently in two processes (see §4).

## 3. Per-VM raw excerpts

### ubuntu2404 — Ubuntu 24.04, 6.8.0-86-generic (`evidence_ubuntu2404.txt`)
```
active LSM: lockdown,capability,landlock,yama,apparmor,bpf   (bpf added via lsm= cmdline + reboot)
map_type ringbuf is available ; BTF present ; cgroup2fs
attach strategy: lsm/file_open   → produced: 5, syscollector delivered=5, fim dropped=0
attach strategy: kprobe/vfs_open → produced: 5, syscollector delivered=5
EXEC pid=1629 ppid=1210 cgroup_id=4302 comm=echo   ; stat spike37396.test = 4302  (MATCH)
caps: cap_bpf cap_perfmon cap_sys_admin cap_dac_read_search
```

### alma9 — AlmaLinux 9.7, 5.14.0-611.54.6.el9_7 (`evidence_alma9.txt`)
```
active LSM: lockdown,capability,landlock,yama,selinux,bpf   (default — no change needed)
map_type ringbuf is available ; BTF present ; cgroup2fs ; libbpf-devel from CRB repo
attach strategy: lsm/file_open   → produced: 5, delivered=5
attach strategy: kprobe/vfs_open → produced: 5, delivered=5
EXEC … cgroup_id=4829 ; stat spike37396.test = 4829  (MATCH)
```

### alma8 — AlmaLinux 8.10, 4.18.0-553 el8_10 (`evidence_alma8.txt`) — the backport verdict
```
active LSM: capability,yama,selinux,bpf   (default)
map_type ringbuf is available   ← RHEL-8 4.18 BACKPORT CONFIRMED
BTF present ; cgroup v1 (tmpfs)
attach strategy: lsm/file_open   → produced: 5, delivered=5   (loaded+emitted despite bpftool
                                                              feature-probe reporting lsm "NOT available")
attach strategy: kprobe/vfs_open → produced: 5, delivered=5
EXEC pid=21094 … comm=echo
caps: cap_bpf cap_perfmon cap_sys_admin cap_dac_read_search
```

### amazonlinux2 — 5.10.260 (extras) and 4.14.336 (default) (`evidence_amazonlinux2.txt`)
```
DEFAULT 4.14.336 : NO BTF ; ringbuf/helpers all absent ; cgroup v1 ; no cap_bpf/perfmon → EXCLUDED
EXTRAS  5.10.260 : active LSM capability,lockdown,yama,selinux,bpf ; BTF ; ringbuf available
   CONFIG_BPF_LSM=y ; CONFIG_DEBUG_INFO_BTF=y ; CONFIG_LSM="…,bpf"
   first run: map 'rb' create EPERM (memlock 64 KiB)  →  after setrlimit fix:
   attach strategy: lsm/file_open   → produced: 5, delivered=5
   attach strategy: kprobe/vfs_open → produced: 5, delivered=5
```

## 3.5 Path-prefix filtering on-kernel, both attach paths [Vm]

After the PoC was updated to emit the **full absolute path** (`bpf_d_path` in the LSM variant, the production dentry walker in the kprobe variant), path-prefix filtering works **on real kernels, on both attach paths** (AlmaLinux 9.7, 5.14-el9). Under boundary (b) this is what a single module needs to filter its **own** stream; it is not a shared-stream fan-out demonstration (see ADR-001 OQ-5 on the stale "one event stream" wording). The measured capture:

```
attach strategy: lsm/file_open     (path via bpf_d_path)
  [syscollector] cgroup_id=3913 path=/etc/poc_test
  [syscollector] cgroup_id=3913 path=/tmp/poc_test
  [fim         ] cgroup_id=3913 path=/etc/poc_test        <- fim sees ONLY /etc/*
  produced: 5 | fim delivered=2 | syscollector delivered=5 | dropped=0

attach strategy: kprobe/vfs_open   (path via manual dentry walker)
  [fim         ] cgroup_id=3913 path=/etc/poc_test        <- same: fim only /etc/*
  produced: 5 | fim delivered=2 | syscollector delivered=5 | dropped=0
```
- `fim` (prefix `/etc`) received exactly the two `/etc/poc_test` events; the unfiltered consumer received all five, with a correlation key on every event. **What this proves under (b): full-path reconstruction works on both attach paths (`bpf_d_path` on LSM, dentry walker on kprobe), so a module can filter its own stream by path prefix on-kernel.** It does not close acceptance criterion 5 (which assumed one shared stream); that wording is flagged for restatement in ADR-001 OQ-5.
- **`bpf_d_path` per-hook acceptance for `lsm/file_open` is now exercised and passes** on 5.14-el9 (the LSM variant uses it and emits correct absolute paths). The AL2 `path_unlink` rejection case remains covered by the engine's `_dpath`/`_walk` fallback (not re-tested here).

## 3.6 Container-runtime dimension — real Docker container [Vm]

Ran on AlmaLinux 9.7 (5.14-el9, cgroup **v2**) with **Docker 29.6.2** (backed by **containerd** `io.containerd.runc.v2` + runc, **cgroup driver = systemd**). A busybox container created files (`/etc/spikecont_*`) while the PoC (kprobe path) captured events (`evidence_alma9_container.txt`):

```
container cgroupfs: /sys/fs/cgroup/system.slice/docker-07535f33….scope
container cgroup st_ino (userspace): 5351

events emitted from INSIDE the container:
  [syscollector] pid=4618 cgroup_id=5351 path=/etc/spikecont_1
  [fim         ] pid=4618 cgroup_id=5351 path=/etc/spikecont_1
  ...
distinct cgroup_id for container events: 5351
```
- **`cgroup_id` of the in-container event (5351) == the container's cgroupfs `st_ino` (5351).** The correlation-key join #37382 relies on holds for a real container, under the **systemd cgroup driver** on **cgroup v2** — answering the "does the driver change cgroup_id semantics?" question: no, the identity holds.
- The full path (`/etc/spikecont_N`) was reconstructed correctly for a file **inside** the container's mount namespace by the kprobe walker, and the `/etc` prefix filter matched container events too (`fim` received them).
- PIDs are **host-namespace** PIDs (4618…), confirming the eBPF component emits host-side identity as designed.
- **Coverage note:** Docker (over containerd/runc) is exercised; **containerd is the underlying runtime**, so both are effectively covered. **CRI-O was NOT tested** (needs OpenShift/K8s — unreachable here). cgroup **v1** container correlation remains the documented gap (`cgroup_id` ambiguous, `RT_F_CGROUP_V1`).

## 4. Still open / not measured (honest)

- **ubuntu2004 (5.4)** — [UNREACHABLE] this session. The VM boots, but its SSH is unreachable over the WSL→VirtualBox NAT — both the `0.0.0.0` port-forward rebind (which works for all 5 other VMs) and vagrant's own `vagrant ssh` fail with "banner exchange timeout", including after a clean `vagrant reload`. This is a box/NAT-specific infra fault, not a kernel finding. The 5.4 exclusion therefore rests on the verified ringbuf floor (5.8, see matrix row Ubuntu 20.04), not a fresh on-kernel measurement. Honest status: not faked.
- **`bpf_d_path` per-hook acceptance** — now exercised for `lsm/file_open` on 5.14-el9 (§3.5, passes). Not yet exercised for `path_unlink`/`path_rename` (the AL2 rejection case); the engine's `_dpath`/`_walk` fallback covers it.
- **al2023 (6.1)** — box available, not run (time). Expected ≥ el9 behavior.
- **SELinux `.te` / AppArmor confinement** — not tested (all runs as unconfined root). Note: alma8/alma9 run SELinux enforcing and BPF load succeeded for root; a confined agent domain policy is still to be authored.
- **Network event class** — remains a written probe (design), no PoC.
- **CRI-O runtime** — not tested (needs OpenShift/K8s). Docker+containerd covered (§3.6).
- **cgroup driver `cgroupfs`** (vs systemd) — not separately tested; systemd driver measured (§3.6). The `cgroup_id`==`st_ino` identity is a kernel/cgroupfs property, so the driver only changes the path layout, not the id — but not independently confirmed here.
- **Two-process concurrent load — the core mechanic of boundary (b) — NOT exercised.** Every on-kernel run loaded ONE BPF object in ONE process. Option (b) requires two processes each loading their own programs on disjoint hooks concurrently (FIM = file hooks in `wazuh-syscheckd`; Syscollector = exec/network hooks inside `wazuh-modulesd`). That concurrency was not tested. Straightforward to test (two PoC instances with different `type_mask`s on one VM) and worth doing before implementation.

## 5. Viability verdict

**On-kernel evidence supports the spike as feasible on the target fleet — YES, with caveats.**

- The extraction mechanics hold: a shared eBPF library with an `.o` carrying both LSM and kprobe variants, the loader selecting the right one per kernel and autoloading only the requested hooks, **loads, attaches, and emits real events on every capable kernel measured: 6.8, 5.14-el9, 5.10, and 4.18-el8** — spanning the realistic Tier-1/2 floor including **RHEL-8**. Under boundary (b) each module links that library and drives its own load/attach of only its hooks, consuming its own stream (all runs here exercised a single such instance; see the two-process caveat below).
- The correlation-key contract is sound: **`cgroup_id`==cgroupfs `st_ino` on cgroup v2** (proven twice, plus a real Docker container in §3.6); v1 correctly degrades to "ambiguous" per the `RT_F_CGROUP_V1` design.
- Two design corrections are now evidence-based, not assumed: **replace the numeric ≥5.8 gate with capability probes** (RHEL-8 4.18 is fully capable), and **treat kprobe as the portable default with LSM as a per-distro-conditional upgrade** (default-on for el8/el9/AL2-5.10, opt-in on Ubuntu). One new hard requirement surfaced: **raise `RLIMIT_MEMLOCK` on 5.10-class kernels**.
- Path-prefix filtering works on-kernel on **both** attach paths (§3.5), with `bpf_d_path` exercised for `lsm/file_open` — enough for a module to filter its own stream. This does not exercise a shared stream (none exists under (b)); acceptance criterion 5's "one event stream" wording is flagged for restatement (ADR-001 OQ-5).
- Caveats: the **two-process concurrent load** that boundary (b) actually ships — two daemons each loading their own programs on disjoint hooks at once — was **not exercised** (all runs were single-object/single-process; see §4); the AL2 *default* 4.14 kernel is **excluded** (no BTF/ringbuf) — AL2 needs the 5.10 extras kernel; cgroup-v1 hosts need a non-cgroup_id container key (aligned with #37382, see `03-event-contract-spec.md §7b`); `bpf_d_path` acceptance for `path_unlink`/`path_rename` and MAC confinement policy remain to be validated with the real engine.
