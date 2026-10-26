# Prebuilt `rt_file.bpf.o`

`CMakeLists.txt` copies `prebuilt/<arch>/rt_file.bpf.o` into `build/lib/` when it
exists, in preference to compiling the object. This directory is the supply
route for it, because the packaging pipeline cannot compile one:

- The compile branch needs `clang`, libbpf development headers, and a usable
  `vmlinux.h`. The agent's package images are `centos:6` and `debian:7`, which
  have no route to a clang new enough for CO-RE, so that branch can never run
  there.
- The vendored per-architecture `vmlinux.h` cannot stand in for a real one. It
  is a **reduced** dump: it defines no cgroup types at all — no `struct cgroup`,
  no `css_set`, no `cgroup_subsys_state` — and its `task_struct` has no
  `cgroups` member, on `x86` and `arm64` alike. `rt_file.bpf.c` has therefore
  never compiled against it on any architecture. (Beware a misleading grep:
  `css_set *cgroups` *does* appear in that file, inside
  `struct task_struct__safe_rcu`, not inside `task_struct`.) `CMakeLists.txt`
  probes it for `struct css_set` rather than merely checking it exists, so this
  corrects itself if the vendored header is ever fixed.

Without an object here, `rt_open()` finds nothing on a packaged agent and the
whole container FIM event path takes its "no eBPF engine" degradation. That is a
warning in `ossec.log` since `c0e5f162bb`, but it is still the feature not
running.

Committing a binary to a source repository is not where this should end up. The
better route is the one `modern.bpf.o` already takes: build it in the same
out-of-repo image (clang-15, issue #28626) and ship it inside
`libbpf-bootstrap.tar.gz`, so `external/CMakeLists.txt` finds it the same way.
That needs a deps-pipeline change and a `DEPS_VERSION` bump, which cannot be
done from this repository — hence the committed objects for now. `CMakeLists.txt`
is deliberately left preferring a prebuilt over compiling, so a deps-shipped
object can take over later without rearranging the gate.

## Directories

| Directory | `CMAKE_SYSTEM_PROCESSOR` | Notes |
| --- | --- | --- |
| `x86/` | anything not `aarch64` | |
| `arm64/` | `aarch64` | |

The split is required, not tidiness: the object is compiled with
`-D__TARGET_ARCH_<arch>` against that architecture's `vmlinux.h`, so an x86
object's CO-RE relocations and `pt_regs` field offsets are wrong on arm64. It
would be copied into place and then fail to load — and that failure is
indistinguishable from "this host has no eBPF".

## Refreshing one

**No toolchain for the target architecture is required.** A BPF object is
architecture-independent ELF; the only arch-dependent inputs are
`-D__TARGET_ARCH_<arch>` and which `vmlinux.h` is on the include path. So both
objects can be produced from one machine, given each architecture's header.

Getting a header needs a running host of that architecture, but nothing more
than SSH: `/sys/kernel/btf/vmlinux` is world-readable and `bpftool btf dump`
needs no root. BTF parsing is itself arch-independent, so a host of *either*
architecture can dump a BTF blob copied from the other.

```sh
# 1. one header per architecture, from a real host of that architecture
ssh <x86_64-host>  'bpftool btf dump file /sys/kernel/btf/vmlinux format c' > x86/vmlinux.h
ssh <aarch64-host> 'bpftool btf dump file /sys/kernel/btf/vmlinux format c' > arm64/vmlinux.h

# 2. compile both, from anywhere with clang and libbpf headers
clang -O2 -g -target bpf -D__TARGET_ARCH_x86   -Iinclude -Ix86   -c bpf/rt_file.bpf.c -o prebuilt/x86/rt_file.bpf.o
clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 -Iinclude -Iarm64 -c bpf/rt_file.bpf.c -o prebuilt/arm64/rt_file.bpf.o

# 3. the invariant that decides whether it loads on a legacy kernel at all
tools/check_bpf_symbols.sh prebuilt/x86/rt_file.bpf.o
tools/check_bpf_symbols.sh prebuilt/arm64/rt_file.bpf.o

# 4. record what they were built from, or CMake reports them stale
for a in x86 arm64; do
  printf '%s %s\n' "$(sha256sum bpf/rt_file.bpf.c | cut -d' ' -f1)" \
                   "$(sha256sum include/rt_event_contract.h | cut -d' ' -f1)" \
    > "prebuilt/$a/rt_file.bpf.o.sources.sha256"
done
```

Prefer a **recent** kernel's header. CO-RE resolves field offsets against the
running kernel at load time, so a newer header is the portable direction: the
committed x86 object is built from a 6.6 header and verified to load on
4.18 (CentOS Stream 8). A header older than the code needs can simply fail to
compile.

Then **confirm each object actually loads** — `bpftool prog loadall <obj>
/sys/fs/bpf/t` as root, which must exit 0 and pin all five programs — and update
the `.github/actions/check_files/*.csv` manifests in the same change. There are
two Linux agent manifests today, `deb_linux_agent_amd64.csv` and
`rpm_linux_agent_amd64.csv`, so only the `x86` object has rows; an arm64 or i386
manifest would need its own row added when it comes back (`CMakeLists.txt`
produces an object for `x86_64` and `aarch64` and nothing else). The checker
exits non-zero both for an installed file no row lists and for a listed file the
build did not produce, so the object and its rows have to land together.

The rows carry the object's **real size**, with the usual `0.1` tolerance. A row
whose `size_bytes` is 0 is skipped by the size comparison entirely —
`check_files.py` treats 0 as falsy — which is what these rows used to carry, and
it meant a truncated or empty object passed the check as long as its owner,
group and mode were right. Refreshing an object therefore means updating its
size in both manifests; the tolerance absorbs an ordinary recompile, not a
missing file.

Rebuild whenever `bpf/rt_file.bpf.c` or `include/rt_event_contract.h` changes.
A mismatched event ABI is refused at `rt_open()` by the guard in `1f6ecea90f`,
and a stale object is now reported at configure time by comparing the digest
written in step 4 — but neither catches a *silently wrong* one, which is what
step 3 is for.
