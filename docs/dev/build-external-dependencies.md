# Build External Dependencies

This document describes the GitHub Actions workflow that rebuilds Wazuh's vendored external dependencies (curl, openssl, rocksdb, …) across every platform we ship, and produces the consolidated `externals-all.tar.gz` blob that gets published to `packages.wazuh.com/deps/<DEPS_VERSION>/`.

Workflow file: [`.github/workflows/5_builderpackage_externals.yml`](../../.github/workflows/5_builderpackage_externals.yml)

Supporting scripts under `packages/externals/`:

| File | Purpose |
|------|---------|
| `dependencies.json` | Inventory: version, revision, URL, sha256, archive format, patches, targets, platforms, CPE, purl and license of every `EXTERNAL_RES` dependency. |
| `patches/<dep>/` | Wazuh changes to upstream sources, applied with `git apply` after download. |
| `deps.py` | Inventory tool: `check` (schema and names against `make print-EXTERNAL_RES`), `flatten` (bash arrays for the builder images), `readme` (README table), `sbom` (CycloneDX), `manifest` (set `manifest.json`), `drift` (inventory against the published manifest). |
| `build_external.sh` | Container-side build script. Downloads every dependency of the leg from the inventory, checks its sha256, applies its patches, and runs the per-leg build; `libbpf-bootstrap` comes from the `build-ebpf` job and the embedded Python from its own set, see [Caveats](#caveats). |
| `generate_external.sh` | Wrapper that flattens the inventory, runs `build_external.sh` and packs the result into `externals-<leg>.tar.gz` with the S3 layout `make deps` expects. |
| `ebpf/build_ebpf.sh` | Builds `libbpf-bootstrap.tar.gz` (`modern.bpf.o` + `libbpf.so`) for amd64, aarch64, arm32, i386 and ppc64le on one x86_64 host, with clang 20 and Zig. See [libbpf-bootstrap](#libbpf-bootstrap-is-built-by-the-build-ebpf-job). |
| `smoke_build.sh` | Sanity check: builds the agent/manager from source against the freshly built consolidated tree to confirm the precompiled tarballs are actually consumable. |

## When to use it

- You changed `packages/externals/dependencies.json` (a version bump, a new dependency, a patch).
- You need to rebuild the whole set (e.g. after a toolchain change that affects how everything compiles).

The output of a successful run is the artifact you upload to `packages.wazuh.com/deps/<new-DEPS_VERSION>/`; the same PR then bumps `DEPS_VERSION` in `src/Makefile`, see [Publishing](#publishing-a-new-deps_version--the-safe-order).

## Running the workflow

From the Actions UI: pick **5.X - Package - Build external dependencies**, click **Run workflow**, choose the branch.

Or from the CLI:

```bash
# Build every dependency of the branch's dependencies.json for the set that will be published as 5/externals/<N>.
gh workflow run 5_builderpackage_externals.yml --ref <branch> -f deps_version=5/externals/<N>
```

### Inputs

| Input | Purpose | Default |
|-------|---------|---------|
| `deps_version` | Set this build will be published as, `5/externals/<number>` (e.g. `5/externals/2`); written into `manifest.json`. | `""` (`unassigned`) |
| `docker_image_tag` | GHCR builder image tag for the Linux legs. `auto` derives it from `VERSION.json`; `developer` uses the branch name; anything else is a literal tag. | `auto` |

There is intentionally no per-leg dispatch input. A deps release is whole-or-nothing — partial output would publish a tarball that breaks `make deps` on any platform whose leg is missing. To re-run a single failed leg, use GitHub's **Re-run failed jobs** on the workflow run.

## What runs

The `build-externals` matrix is fixed at 7 entries:

| Leg | Target | Runner | Notes |
|-----|--------|--------|-------|
| `rpm-amd64` | agent | `wz-linux-amd64` | CentOS 6 agent builder image (glibc 2.12 baseline). |
| `rpm-arm64` | agent | `wz-linux-arm64` | CentOS 6 agent builder image. |
| `macos-intel64` | agent | `macos-14-large` | Native macOS build. Agent-only. |
| `macos-arm64` | agent | `macos-14` | Native macOS build. Agent-only. |
| `windows-i686` | agent | `wz-linux-amd64` | MinGW cross-compile inside the `compile_windows_agent` image (ubuntu:22.04, same one the official windows agent build uses). Agent-only. |
| `rpm-amd64` | manager | `wz-linux-amd64` | CentOS 7 manager builder image (glibc 2.17). |
| `rpm-arm64` | manager | `wz-linux-arm64` | CentOS 7 manager builder image. |

Why each Linux arch runs twice: the manager image (CentOS 7) can build a couple of deps the agent image (CentOS 6) can't (newer toolchain), but the agent image's older glibc is the safe baseline for everything else. Both legs build their full dep set; the `consolidate` job picks the agent-image copy when both exist, so we ship glibc-2.12-compatible binaries wherever possible.

We don't build separate `deb` legs because rpm glibc is forward-compatible with deb's.

A separate `build-ebpf` job runs `ebpf/build_ebpf.sh` on `ubuntu-24.04` for every Linux arch.

## Jobs

```
build-externals (matrix, 7 jobs) ─┐
                                  ├─► consolidate ──► smoke-build (5 jobs)
build-ebpf ───────────────────────┘
```

- **`build-externals`** — each leg downloads its dependencies from the inventory (sha256 checked, patches applied), runs the build, and uploads `externals-<leg>-<target>.tar.gz`. A download, checksum or patch failure fails the leg.
- **`build-ebpf`**: installs clang 20 (`apt.llvm.org`) and the Zig version pinned in `build_ebpf.sh`, runs it, and uploads `libbpf-bootstrap` (`<arch>/libbpf-bootstrap.tar.gz`).
- **`consolidate`** — downloads every per-leg tarball, merges into the canonical `libraries/{linux,darwin,windows,sources}/` layout, places the `build-ebpf` tarballs under `libraries/linux/<arch>/`, writes `manifest.json` (the inventory entries plus the sha256 of every file) with `deps.py manifest`, and uploads `externals-all.tar.gz` (the artifact you publish to `packages.wazuh.com/deps/<version>/`).
- **`smoke-build`** — for each of the 4 Linux combinations (amd64/arm64 × agent/manager) plus a windows-i686 leg, pulls `externals-all.tar.gz`, points `make deps RESOURCES_URL=file://…` at the local tree, then runs the real Wazuh build inside the matching builder image (`pkg_rpm_<target>_builder_<arch>` for Linux, `compile_windows_agent` for windows). Confirms the precompiled tarballs you just packed actually get consumed. Emits `::warning::` for any dep that fell back to source compile — that means the binary was packed at a path `src/external/CMakeLists.txt` doesn't expect. The windows leg is what catches host-side tools shipped in `libraries/windows/<dep>.tar.gz` (e.g. flatbuffers' `flatc`, invoked during `make TARGET=winagent` schema codegen) that were built against a newer glibc/libstdc++ than the consumer image — without it, that mismatch only surfaces downstream when the windows agent build runs.

## Output

Per-leg artifacts (`externals-rpm-amd64-agent`, `externals-macos-arm64-agent`, …) are kept 14 days for debugging.

The artifact to publish is `externals-all` → `externals-all.tar.gz`. Its layout matches the S3 directory it gets uploaded into:

```
manifest.json                            ← what the set contains (deps.py manifest)
libraries/
├── linux/{amd64,aarch64}/<dep>.tar.gz   ← precompiled binaries
├── linux/{arm32,i386,ppc64le}/libbpf-bootstrap.tar.gz
├── darwin/{amd64,aarch64}/<dep>.tar.gz
├── windows/<dep>.tar.gz                 ← no arch subdir for MinGW
└── sources/<dep>.tar.gz                 ← upstream source snapshots
```

`make deps` walks this exact tree; the path layout is not negotiable. If you change `generate_external.sh`'s `S3_PATH` mapping, you must update `PRECOMPILED_RES` in `src/Makefile` to match (and vice versa).

Smoke build logs (`smoke-build-<target>-<arch>`) are also retained 14 days and are the first place to look when a downstream build starts pulling deps from source unexpectedly.

## Dependency matrix

Which dependency each platform/target actually builds and links, and how it is
published. The download set per target lives in `EXTERNAL_RES` (`src/Makefile`)
and the build/link guards in `src/external/CMakeLists.txt`; the two are kept in
sync — a dep is downloaded for exactly the targets that compile it.

Legend: ✔ built & linked · — not used. Targets: **La** Linux agent · **Lm**
Linux manager/server · **Ma** macOS agent · **Wa** Windows agent (MinGW).

### Universal (every platform and target)

| Dependency | La | Lm | Ma | Wa | Published as |
|------------|----|----|----|----|--------------|
| cJSON | ✔ | ✔ | ✔ | ✔ | precompiled `.a` (source-buildable fallback) |
| openssl | ✔ | ✔ | ✔ | ✔ | precompiled `.a` |
| zlib | ✔ | ✔ | ✔ | ✔ | precompiled `.a` (bundles minizip on non-Windows) |
| sqlite | ✔ | ✔ | ✔ | ✔ | precompiled `.a` (source-buildable fallback) |
| libyaml | ✔ | ✔ | ✔ | ✔ | precompiled `.a` |
| curl | ✔ | ✔ | ✔ | ✔ | precompiled `.a` |
| libpcre2 | ✔ | ✔ | ✔ | ✔ | precompiled `.a` |
| flatbuffers | ✔ | ✔ | ✔ | ✔ | precompiled `.a` + `flatc` |
| nlohmann | ✔ | ✔ | ✔ | ✔ | **source-only (header)** |
| zstd | ✔ | ✔ | ✔ | ✔ | precompiled `.a` |
| jwt-cpp | ✔ | ✔ | ✔ | ✔ | **source-only (header)** |
| rapidjson | ✔ | ✔ | ✔ | ✔ | **source-only (header)** |

### Shared build-time dependency (downloaded on all targets, linked non-Windows)

`shared.h` pulls in `shared/include/bzip2_op.h` → `<bzlib.h>` on every target (and
the bzip2 unit-test wrapper needs the header too), so the source is downloaded
everywhere — including the Windows agent. Only non-Windows targets link `libbz2`
(`external/CMakeLists.txt` builds `ext_bzip2` under `NOT IS_WINDOWS`).

| Dependency | La | Lm | Ma | Wa | Published as |
|------------|----|----|----|----|--------------|
| bzip2 | ✔ | ✔ | ✔ | ✔ | precompiled `.a` (linked on non-Windows only). Agent/server link it via `shared/src/bzip2_op.c`→`libwazuhext`; server also builds rocksdb (`WITH_BZ2`). |

### Linux agent only

Consumers are `data_provider`/sysinfo, `syscheckd` (whodata), `rootcheck` — all
agent-only subdirectories. The server's `wazuh_modules` builds
inventory_sync_server/keystore_server/vulnerability_scanner instead, so it links none of these.

| Dependency | La | Lm | Ma | Wa | Published as |
|------------|----|----|----|----|--------------|
| audit-userspace | ✔ | — | — | — | precompiled `.a` (gated by `ENABLE_AUDIT`, agent-only) |
| procps | ✔ | — | — | — | precompiled `.a` (source-buildable fallback) |
| libdb | ✔ | — | — | — | precompiled `.a` |
| popt | ✔ | — | — | — | precompiled `.a` (rpm dependency) |
| lua | ✔ | — | — | — | precompiled `.a` (rpm dependency) |
| rpm | ✔ | — | — | — | precompiled `.a` |
| dbus | ✔ | — | — | — | precompiled `.a` |
| libbpf-bootstrap | ✔ | — | — | — | precompiled `.o` + `.so` (`build-ebpf` job) |

### macOS agent only

| Dependency | La | Lm | Ma | Wa | Published as |
|------------|----|----|----|----|--------------|
| libplist | — | — | ✔ | — | precompiled `.a` |

### Linux server (manager) only

| Dependency | La | Lm | Ma | Wa | Published as |
|------------|----|----|----|----|--------------|
| cpython | — | ✔ | — | — | own set (`5_builderpackage_embedded-python.yml`, `PYTHON_DEPS_VERSION`) |
| libffi | — | ✔ | — | — | precompiled `.a` (cpython/ctypes) |
| jemalloc | — | ✔ | — | — | precompiled `.so` |
| rocksdb | — | ✔ | — | — | precompiled `.so` |
| simdjson | — | ✔ | — | — | precompiled `.a` |
| abseil-cpp | — | ✔ | — | — | precompiled `.a` |
| re2 | — | ✔ | — | — | precompiled `.a` (needs abseil) |
| spdlog | — | ✔ | — | — | precompiled `.a` |
| yaml-cpp | — | ✔ | — | — | precompiled `.a` |
| pugixml | — | ✔ | — | — | precompiled `.a` |
| libmaxminddb | — | ✔ | — | — | precompiled `.a` |
| protobuf | — | ✔ | — | — | precompiled `.a` |
| date | — | ✔ | — | — | precompiled `.a` (needs curl) |
| fmt | — | ✔ | — | — | precompiled `.a` |
| minizip | — | ✔ | — | — | precompiled `.a` — **lives in the zlib tree**, built on the non-Windows legs (incl. agent) so it ships inside `zlib.tar.gz` |
| asio | — | ✔ | — | — | **source-only (header)** |
| expected-lite | — | ✔ | — | — | **source-only (header)** |
| llhttp | — | ✔ | — | — | precompiled `.a` |
| restinio | — | ✔ | — | — | **source-only (header)** |
| RxCpp | — | ✔ | — | — | **source-only (header)** |
| taskflow | — | ✔ | — | — | **source-only (header)** |
| concurrentqueue | — | ✔ | — | — | **source-only (header)** |
| fast_float | — | ✔ | — | — | **source-only (header)** |
| cpp-httplib | — | ✔ | — | — | **source-only (header)** |
| geo_db | — | ✔ | — | — | data blob (MaxMind GeoLite2), sources bucket |
| tzdata | — | ✔ | — | — | data (IANA tz), sources bucket |

### Test frameworks (downloaded on all targets, compiled only into test binaries)

These are *compiled* only when `UNIT_TEST`/`WAZUH_ENGINE_TEST` is set, but they are
*downloaded* unconditionally: the deps step (`make deps TARGET=…`) does not pass
`TEST=1`, and the unit-test CI consumes the same per-(os,arch) bundle, so gating
the download behind a flag drops them from the bundle and breaks every test build.

| Dependency | Downloaded for | Compiled into | Published as |
|------------|----------------|---------------|--------------|
| googletest | all targets | agent + server tests | precompiled `.a` |
| benchmark | all targets | server tests | precompiled `.a` |

> **Header-only deps** (nlohmann, jwt-cpp, cpp-httplib, rapidjson, RxCpp, taskflow,
> concurrentqueue, fast_float, asio, expected-lite, restinio) carry no compiled artifact — they belong only in
> `libraries/sources/`. The generation snapshot still copies their (binary-free)
> trees into `libraries/<os>/<arch>/`; pruning those redundant per-arch copies is
> tracked as follow-up work for #36247.

## Publishing a new DEPS_VERSION — the safe order

5.x publishes two kinds of sets, numbered from 1: `deps/5/externals/<n>` (this workflow, the C/C++ libraries) and `deps/5/python/<n>` (`5_builderpackage_embedded-python.yml`, the embedded Python and its wheels). `src/Makefile` points at one of each: `DEPS_VERSION = 5/externals/<n>` and `PYTHON_DEPS_VERSION = 5/python/<n>`. A set may be rebuilt while no merged branch points at it; once one does, it is never modified, and a change is the next number. The 4.x sets (`55`, `4.10.4`) and older ones (`54`, `99-37702`, …) stay where they are.

1. Open a branch and edit `packages/externals/dependencies.json` (version, revision, `url`, sha256 of the downloaded archive, patches). Run `python3 packages/externals/deps.py check` and `python3 packages/externals/deps.py readme`, and commit both files.
2. Take the next number (`aws s3 ls s3://…/deps/5/externals/`) and dispatch the workflow with `deps_version=5/externals/<N>`. Keep `DEPS_VERSION` at the currently published set while it runs, see the caveat below.
3. Wait for `build-externals`, `consolidate`, and all `smoke-build` jobs to go green.
4. Download `externals-all.tar.gz` and upload its contents (`manifest.json` and `libraries/…`) to `s3://…/deps/5/externals/<N>/`, never over an existing key (`aws s3api put-object --if-none-match '*'`).
5. Set `DEPS_VERSION = 5/externals/<N>` in `src/Makefile` in the same PR. The drift check (`5_codequality_externals-drift.yml`) then compares the inventory with `deps/5/externals/<N>/manifest.json`.
6. Rebuild and publish the embedded Python against the new set in the same PR (see below): the drift check fails while the Python set was built against another `DEPS_VERSION`.

## Caveats

### Bump `DEPS_VERSION` only after the new set is uploaded

The inventory decides every dependency source, but `DEPS_VERSION` (defined in `src/Makefile`) still decides what the workflow takes from the currently published set: the `libbpf-bootstrap` source tree, fetched with `make EXTERNAL_SRC_ONLY=yes <goals>` together with the embedded Python (from `PYTHON_DEPS_VERSION`) and the other prerequisites of `make deps` (http-request, indexer templates, WCS file and credentials library, from GitHub).

If your branch points `DEPS_VERSION` at the set you're trying to *produce*, those fetches fail and the run fails. Dispatch the workflow while `DEPS_VERSION` points at the *currently published* set, and bump it once the new set is uploaded.

### `libbpf-bootstrap` is built by the `build-ebpf` job

`libbpf-bootstrap` needs clang ≥ 7 with the BPF backend and Linux UAPI headers ≥ 4.13 (`linux/bpf_perf_event.h`), and the legacy agent builder image (CentOS 6 / Debian wheezy era, glibc 2.12) has neither. There is no from-source fallback in `src/external/CMakeLists.txt`: the agent loads `libbpf.so` and `modern.bpf.o` at runtime, so its build does not need them, and `consolidate` ships the copy `build-ebpf` produced.

`ebpf/build_ebpf.sh` compiles `modern.bpf.o` from `src/syscheckd/src/ebpf/src/modern.bpf.c` of the dispatched branch with clang 20, and cross-compiles libbpf `v1.7.0` with Zig against glibc 2.17 (2.19 on ppc64le). Pinned versions (clang, Zig, libbpf tag, `libbpf/vmlinux.h` commit) live at the top of the script; the job reads the Zig version from there. The output is reproducible, so a rebuild of an unchanged source gives the same binaries.

To build it locally on `ubuntu:24.04` with `libelf-dev zlib1g-dev`, `apt.llvm.org/llvm.sh 20` and the pinned Zig:

```bash
bash packages/externals/ebpf/build_ebpf.sh   # writes ./output/<arch>/libbpf-bootstrap.tar.gz
```

### The embedded Python is its own set

`cpython` and the wheels of `framework/requirements.txt` are built by `5_builderpackage_embedded-python.yml` (`framework/cpython/compile.sh`) against the libraries of `DEPS_VERSION`, and published as `deps/5/python/<n>` (`libraries/sources/cpython_<arch>.tar.gz` and `libraries/linux/<arch>/cpython.tar.gz`). `make deps` downloads them from `PYTHON_RESOURCES_URL` (`PYTHON_DEPS_VERSION`), so a `RESOURCES_URL` override (a local mirror, `smoke_build.sh`) does not affect them: set `PYTHON_RESOURCES_URL` too to take Python from elsewhere. Manager only; the agent `EXTERNAL_RES` has no `$(CPYTHON)`. The externals workflow only fetches the Python tree for its configure step and does not ship it. Its inventory entry describes the upstream release that is scanned. To publish a new one (a wheel bump, a new Python, or new libraries):

1. Run `5_builderpackage_embedded-python.yml` with `python_deps_version=5/python/<N>`, with `DEPS_VERSION` already at the externals set it must link against.
2. Upload the contents of its `python-all.tar.gz` (`manifest.json`, with `built_against` and the wheels, and `libraries/…`) to `s3://…/deps/5/python/<N>/`, never over an existing key.
3. Set `PYTHON_DEPS_VERSION = 5/python/<N>` in `src/Makefile`. The drift check compares the inventory's `cpython` entry and `framework/requirements.txt` with that manifest, and its `built_against` with `DEPS_VERSION`.

### macOS and Windows are agent-only

There are no manager builder images for darwin or windows. The matrix reflects this; do not add manager entries for those systems.

### Source-rebuild fallbacks are silent

`src/Makefile` lines 602 and 650 (the precompiled-fetch rules) are `-@ … || true` — a missing precompiled tarball is non-fatal and CMake falls back to source compilation. That means a packing-path bug (binary placed under `libraries/linux/amd64/` when `make deps` looked for `libraries/linux/x86_64/`, say) won't fail `make deps` outright. The smoke-build's "Analyze dependency usage" step is what catches this, by grepping the build log for `Performing build step for '<dep>_external'` / `Building … ext_<dep>.dir/` and emitting `::warning::` for each.

Treat any smoke-build warning as a blocker. The whole point of a deps release is that everything ships precompiled.

### Consolidate tie-breaking

On Linux, both the agent and manager legs build the agent dep set, so each Linux arch yields two copies of every agent dep. `consolidate` processes manager legs first, then agent legs, and the first writer wins for each dep — so the agent (older glibc) copy is the one that ships when both exist. For manager-only deps (cpython, jemalloc, simdjson, etc. — see `EXTERNAL_RES` in `src/Makefile`), the manager copy is the only candidate and ships unchanged.

Source zips are byte-identical across legs; first writer wins is fine for those.

### Debugging a single failed leg

Use GitHub's **Re-run failed jobs** on the workflow run rather than dispatching a fresh run. Re-running a single matrix entry uses the same triggering branch + inputs and slots into the same overall run, so `consolidate` still runs against the full set when every leg has eventually succeeded.

If a leg keeps failing locally, you can reproduce it by pulling the same builder image from GHCR and running `packages/externals/generate_external.sh --system <sys> --architecture <arch> --target <agent|manager> --verbose` against a checkout of your branch.

## Related

- [Package generation](package-generation.md) — `generate_package.sh`, the script that turns built sources + deps into shipped `.rpm`/`.deb`.
- [`src/Makefile`](../../src/Makefile) — `DEPS_VERSION`, `RESOURCES_URL`, `PRECOMPILED_RES`, `EXTERNAL_RES`.
- [`src/external/CMakeLists.txt`](../../src/external/CMakeLists.txt) — the consumer side; decides which deps short-circuit to precompiled archives vs build from source.
