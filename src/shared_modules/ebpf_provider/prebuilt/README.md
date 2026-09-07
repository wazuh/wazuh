# Prebuilt `rt_file.bpf.o`

`CMakeLists.txt` copies `prebuilt/<arch>/rt_file.bpf.o` into `build/lib/` when it
exists, in preference to compiling the object. This directory is the supply
route for it, because the packaging pipeline cannot compile one:

- `libbpf-bootstrap` is fetched as a **precompiled** external resource, so
  `modern.bpf.o` arrives prebuilt and `external/CMakeLists.txt` short-circuits
  its `ExternalProject` — which is also what leaves the vendored per-architecture
  `vmlinux.h` absent.
- The compile branch then needs `clang`, libbpf development headers, and either
  that vendored `vmlinux.h` or a working `bpftool` plus `/sys/kernel/btf/vmlinux`.
  A package-build container has none of those.

Without an object here, `rt_open()` finds nothing on a packaged agent and the
whole container FIM event path takes its "no eBPF engine" degradation. That is a
warning in `ossec.log` since `c0e5f162bb`, but it is still the feature not
running.

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

On a host of the target architecture, with clang, libbpf headers and either the
vendored `vmlinux.h` or a usable `bpftool`:

```sh
cd src
make deps TARGET=agent -j"$(nproc)"
make build TARGET=agent -j"$(nproc)"
cp build/lib/rt_file.bpf.o shared_modules/ebpf_provider/prebuilt/<arch>/
```

Then confirm it actually loads (`test/rt_engine_open_test.c` and
`rt_engine_filter_test.c` under `shared_modules/ebpf_provider`, which need root
and a cgroup-v2 kernel), and update the four
`.github/actions/check_files/*.csv` manifests in the same change — the checker
exits non-zero both for an installed file no row lists and for a listed file the
build did not produce, so the object and its rows have to land together. A row
may carry `size_bytes=0`, which skips the size comparison while still asserting
owner, group, mode and permissions.

Rebuild whenever `bpf/rt_file.bpf.c` or `include/rt_event_contract.h` changes:
nothing here detects a stale object, and a mismatched event ABI is refused at
`rt_open()` by the guard in `1f6ecea90f`.
