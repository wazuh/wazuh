# 23 — Container file monitoring on a legacy RHEL-family kernel

What stopped `rt_file.bpf.o` loading on CentOS Stream 8 / RHEL 8, what it took to fix, and what was
measured before and after. Written because none of it was recorded anywhere in this repository:
doc 18 §18.9 closed with *"Not yet validated end to end"*, and the reason it could not be validated
— that the object does not load there at all — lived only in a session note.

Host for every measurement below: `wazuh_agent_centos`, CentOS Stream 8, kernel
**4.18.0-326.el8.x86_64**, a genuine cgroup v1 host, clang 17.0.6, system libbpf 0.5.0.

---

## 23.1 What was actually wrong

Three independent faults. Only the first two had to be fixed; the third turned out not to exist.

### Fault 1 — the verifier's instruction budget (the real one)

Loading logged this, which is what everyone fixated on:

```
Unrecognized arg#0 type PTR
```

**It is a red herring.** For a *static* BPF-to-BPF subprogram that message is non-fatal: the
verifier gives up on BTF argument matching and falls back to walking **into** the callee at every
call site. The fatal error came later in the same log:

```
BPF program is too large. Processed 1000001 insn
processed 1000001 insns (limit 1000000) max_states_per_insn 19 total_states 61836
```

So 4.18 here *does* carry the 5.2 raise of `BPF_COMPLEXITY_LIMIT_INSNS` to 1,000,000 — and the
program exceeded it by one instruction. The cause is structural: `get_path_str_from_path()` is a
320-iteration unrolled dentry walk of ~13,800 instructions, and it is reachable **three times** per
program (once directly, twice via `get_task_cwd()` inside `submit_event()`). Walked in at each
site, that is ~41,500 raw instructions before branch forking.

`#define statfunc static inline` left the placement decision to clang. Measured on the object as it
was, `.text` held exactly three outlined functions — not the four the review assumed:

| symbol | bytes | instructions |
|---|---|---|
| `get_path_str_from_path` | 110,568 | 13,821 |
| `submit_event` | 2,312 | 289 |
| `current_container_cgroup_id` | 552 | 69 (legal — takes `void`) |

`get_inode_dev` and `get_task_cwd` were already inlined by clang 17, so they were *latent*
offenders only. This is why the fix includes a build-time assertion rather than relying on source
discipline: which functions get outlined is a compiler decision, and **clang 18 outlines a
different set from clang 17 on the same source**.

### Fault 2 — the engine binds the host's libbpf

`rt_engine.c` resolved libbpf by bare soname, and no Wazuh binary carries an RPATH:

```c
dlopen("libbpf.so.1", RTLD_NOW) ?: dlopen("libbpf.so", RTLD_NOW)
```

On this host `/usr/lib64/libbpf.so.1` **does not exist** (the distro ships `libbpf.so.0.5.0`), so
the first call always fails. The second only resolves at all when `libbpf-devel` is installed, and
then binds 0.5.0, which is missing `bpf_object__next_program` — one of the engine's 18 mandatory
symbols. On a stock host both calls fail and the log says only `dlopen(libbpf) failed`.

The agent ships its own libbpf at `/var/ossec/lib/libbpf.so` (SONAME `libbpf.so.1`, carrying every
symbol needed). Nothing was asking for it.

### Fault 3 — BPF LSM: not a fault

The original analysis held that `is_bpf_lsm_active()` wrongly selects the LSM program here, because
`bpftool feature probe` reports `program_type lsm is NOT available`. **That probe is misleading**:
it tries a trivial LSM program with no `attach_btf_id`, which cannot load on any kernel. The real
`SEC("lsm/file_open")` program has a valid attach target and loads *and attaches* fine. This host
has `CONFIG_BPF_LSM=y` and `capability,yama,selinux,bpf` active, so `is_bpf_lsm_active()` makes the
**right** call, and the LSM program is the one that actually serves `RT_EV_FILE_OPEN` here.

The LSM program had only ever failed as collateral of the whole object failing to load.

`is_bpf_lsm_active()` still tests the wrong thing in principle — a string list rather than
loadability — and hardening it is worthwhile on its own merits, but it is **not** required for
RHEL 8 and nothing here should claim otherwise.

---

## 23.2 The fix

### One subprogram, all-scalar, global

The walker stays outlined — it must, as inlining it three times per program is what overflows
clang's ±32,767 branch displacement — but it becomes a **global** (external-linkage) `noinline`
function whose every parameter is an integer:

```c
subprogfunc long rt_walk_dentry(__u64 dentry_addr, __u64 vfsmnt_addr, __u32 slot);
```

A global function with arguments the verifier can type is verified **once, on its own**:

```
Validating rt_walk_dentry() func#1...
```

Scalars rather than `struct dentry *` / `struct vfsmount *` deliberately. Scalar parameters are the
only shape accepted by every revision of `btf_check_func_arg_match`, and a typed-pointer signature
would have raised two further unmeasured questions on 4.18: whether `PTR_TO_STACK` is accepted
where a struct pointer is declared, and whether `container_of(vfsmnt, struct mount, mnt)` — pointer
arithmetic on a possible `PTR_TO_BTF_ID` — is rejected outright. Nothing is lost by laundering the
addresses through `__u64`, because every dereference in that body is already a
`bpf_probe_read_kernel` via `BPF_CORE_READ`; CO-RE relocations are emitted at the access sites
inside the callee, where the types are fully declared.

> **An earlier conclusion was wrong and cost time.** A repro was thought to prove that a subprogram
> taking `struct path *` loads on 4.18. It proved no such thing: it passed
> `(struct path*)PT_REGS_PARM1(ctx)`, which the verifier sees as `SCALAR_VALUE`, not a pointer. No
> pointer-argument design may rest on it.

Everything else becomes `__always_inline`. `submit_event` is only 289 instructions, so inlining it
into five programs is cheap — they grow from 109-160 to 560-597 instructions, far inside the branch
window.

`get_task_cwd()` loses its `struct path pwd` stack local (reading `pwd.dentry` and `pwd.mnt`
separately), and the three kprobes lose their shadow `struct path`s. That removes every
pointer-to-stack question from the file. The only behavioural consequence is that the
`(dentry, mnt)` pair can tear if the task calls `chdir()` between the two reads — immaterial beside
the race the 320-step walk already has.

### Two scratch buffers become two slots

`heaps_map` and `cwd_heap` merge into one `PERCPU_ARRAY` with two entries, selected by the scalar
`slot` argument. Same 2 × 32 KiB per CPU, and `RT_SLOT_EVENT` and `RT_SLOT_CWD` remain as separate
from each other as the two maps were. One map rather than two is not tidiness: a `slot`-driven
choice *between maps* yields `PTR_TO_MAP_VALUE` registers with different `map_ptr`, which 4.18's
`regsafe()` compares, so the branches would never prune against each other and the verifier would
walk the 13,800-instruction loop twice.

### The engine asks for the agent's own libbpf

`rt_filter` gains `libbpf_path`, fed from `CB_RT_LIBBPF_PATH` by the same
`fim_container_baseline_abspath()` route the BPF object path already takes. NULL keeps the old
soname behaviour, so the standalone harness and contract test are unaffected. The engine now also
says which library it bound, and names it when a symbol is missing.

### A build-time assertion, because this is a compiler decision

`tools/check_bpf_symbols.sh` asserts that `.text` contains exactly one function, `rt_walk_dentry`,
and fails the build otherwise. Wired into both the CMake compile branch and the standalone
Makefile. Without it, a future clang silently reintroduces the fault on the one platform no CI job
load-tests. It was verified to reject the pre-fix object and accept the new one under both clang 17
and clang 18.

---

## 23.3 Measured, before and after

| | `.text` functions | per-program insns | verifier cost | load |
|---|---|---|---|---|
| before | 3 | 109-160 | **1,000,001 / 1,000,000** | refused |
| after | **1** | 560-597 | **66,567 / 1,000,000** | **all 5 programs, `RC=0`** |

A ~15× reduction, leaving 93% of the budget unused.

### End to end on 4.18

```
RESULT: rt_open OK
  [engine/INFO] libbpf bound from '/var/ossec/lib/libbpf.so'
  [engine/INFO] eBPF engine ready: 4 program(s) attached, ABI 1.1
  [engine/DEBUG] active LSM list includes "bpf" -> preferring LSM file_open variant
RESULT: v1 controller 'memory' index=4 set rc=0
RESULT: cgroup_id usable=1

EVENT OPEN cgroup_id=6051 mnt_ns=4026531840 comm=touch path=/tmp/wz-validate-host
EVENT OPEN cgroup_id=6083 mnt_ns=4026532222 comm=touch path=/wz-validate-container

expected_cgroup_inode=6083   (/sys/fs/cgroup/memory/docker/9e7dc23ced74...)
```

**This is the first direct evidence that `df2ac9e721` does what it claims.** That commit masks the
reuse generation out of `kernfs_node.id`; the container event's `cgroup_id` is exactly the
container's memory-cgroup `st_ino`, and distinct from the host's. Without the mask the value would
have arrived as `(generation << 32) | 6083` and never matched.

### Portability

| object | built against | loads on |
|---|---|---|
| `prebuilt/x86/rt_file.bpf.o` | 6.6 x86_64 BTF | **4.18.0-326 (CentOS Stream 8)** ✓ |
| `prebuilt/arm64/rt_file.bpf.o` | 6.8 aarch64 BTF | **6.8.0-139 (Ubuntu 24.04 arm64)** ✓ |

The x86 case is the demanding direction — a new header against an old kernel — and is what makes
CO-RE's offset relocation worth relying on. Not directly verified: the x86 object on a modern x86
kernel (the easier direction), and the arm64 object on a legacy arm64 kernel (no such host exists
here).

---

## 23.4 Shipping it

`rt_file.bpf.o` was in **no** packaging manifest and `prebuilt/{x86,arm64}/` were empty, so
container file monitoring had never run from an installed package on **any** operating system — not
a legacy-kernel problem at all. The objects are now committed and listed in the four amd64/arm64
`check_files` manifests.

Two things were learnt while doing it, both pre-existing:

- **The vendored `vmlinux.h` cannot compile this program, on either architecture.** It is a reduced
  dump defining no cgroup types whatsoever — no `struct cgroup`, `css_set` or
  `cgroup_subsys_state` — and its `task_struct` has no `cgroups` member. This is the real cause of
  the long-standing `no member named 'cgroups' in 'struct task_struct'` failure that aborted the
  whole agent build on developer machines. CMake now probes the header for `struct css_set` instead
  of merely checking it exists, so it falls back with a reason rather than attempting a doomed
  compile. (Misleading grep: `css_set *cgroups` *is* in that file — inside
  `struct task_struct__safe_rcu`.)
- **No cross-architecture toolchain is needed.** A BPF object is architecture-independent ELF; the
  only arch-dependent inputs are `-D__TARGET_ARCH_<arch>` and which `vmlinux.h` is used. And since
  BTF parsing is itself arch-independent, a host of *either* architecture can dump a BTF blob
  copied from the other. Both committed objects were compiled on one x86_64 machine.

`CMakeLists.txt` also no longer treats every non-aarch64 architecture as 64-bit x86: i386 was being
handed an object built for the wrong register layout, which would install and then fail to load
indistinguishably from "this host has no eBPF".

---

## 23.5 Still open

- **Amazon Linux 2 remains unverified.** No 4.14 host exists here, and that kernel may lack
  `CONFIG_DEBUG_INFO_BTF` entirely, in which case CO-RE cannot load at all and external BTF
  (BTFHub, via `bpf_object_open_opts.btf_custom_path`) would be needed. The CHANGELOG claim is
  narrowed to what has been measured rather than left asserting it.
- `is_bpf_lsm_active()` tests a string list rather than loadability (§23.1, fault 3).
- No test covers `rt_open()`'s own branches; `CMakeLists.txt` already records that this needs a fake
  libbpf, and this change adds two more branches (libbpf path resolution, the bound-library log).
- Nothing reports which BPF features were detected at startup, so a host where this silently
  degrades still looks the same as one where it was never enabled.
