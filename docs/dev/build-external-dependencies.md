# Build External Dependencies

This document describes the GitHub Actions workflow that rebuilds Wazuh's vendored external dependencies (curl, openssl, rocksdb, …) across every platform we ship, and produces the consolidated `externals-all.tar.gz` blob that gets published to `packages.wazuh.com/deps/<DEPS_VERSION>/`.

Workflow file: [`.github/workflows/5_builderpackage_externals.yml`](../../.github/workflows/5_builderpackage_externals.yml)

Supporting scripts under `packages/externals/`:

| File | Purpose |
|------|---------|
| `external_sources.sh` | Manifest: upstream URL template + archive format + target dir for each dep. |
| `build_external.sh` | Container-side build script. Seeds `src/external/` via `make deps EXTERNAL_SRC_ONLY=yes`, applies overrides from `--dependencies`, runs the per-leg build, and re-ships a prebuilt `libbpf-bootstrap` (the legacy builder images can't compile it — see [Caveats](#libbpf-bootstrap-is-re-shipped-not-rebuilt)). |
| `generate_external.sh` | Wrapper that runs `build_external.sh` and packs the result into `externals-<leg>.tar.gz` with the S3 layout `make deps` expects. |
| `smoke_build.sh` | Sanity check: builds the agent/manager from source against the freshly built consolidated tree to confirm the precompiled tarballs are actually consumable. |

## When to use it

- You need to bump one or more upstream library versions (e.g. CVE patch, new feature).
- You need to refresh the full deps tarball from currently vendored sources (e.g. after a toolchain change that affects how everything compiles).

The output of a successful run is the artifact you upload to `packages.wazuh.com/deps/<new-DEPS_VERSION>/`. A separate PR then bumps `DEPS_VERSION` in `src/Makefile` to point at that new directory.

## Running the workflow

From the Actions UI: pick **5.X - Package - Build external dependencies**, click **Run workflow**, choose the branch.

Or from the CLI:

```bash
# Clean rebuild of every dep from currently vendored sources (no overrides).
gh workflow run 5_builderpackage_externals.yml --ref <branch>

# Override one or more dep versions; bare upstream sources are pulled from
# the URLs in packages/externals/external_sources.sh.
gh workflow run 5_builderpackage_externals.yml --ref <branch> \
  -f dependencies="curl:8.13.0;openssl:3.5.2"
```

### Inputs

| Input | Purpose | Default |
|-------|---------|---------|
| `dependencies` | Semicolon-separated `name:version` overrides. Each named dep is re-fetched from the upstream URL in `external_sources.sh` and replaces what `make deps` extracted. Unlisted deps are rebuilt from the vendored source. | `""` (rebuild only) |
| `docker_image_tag` | GHCR builder image tag for the Linux legs. `auto` derives it from `VERSION.json`; `developer` uses the branch name; anything else is a literal tag. | `auto` |

There is intentionally no per-leg dispatch input. A deps release is whole-or-nothing — partial output would publish a tarball that breaks `make deps` on any platform whose leg is missing. To re-run a single failed leg, use GitHub's **Re-run failed jobs** on the workflow run.

## What runs

The matrix is fixed at 7 entries:

| Leg | Target | Runner | Notes |
|-----|--------|--------|-------|
| `rpm-amd64` | agent | `wz-linux-amd64` | CentOS 6 agent builder image (glibc 2.12 baseline). |
| `rpm-arm64` | agent | `wz-linux-arm64` | CentOS 6 agent builder image. |
| `macos-intel64` | agent | `macos-14-large` | Native macOS build. Agent-only. |
| `macos-arm64` | agent | `macos-14` | Native macOS build. Agent-only. |
| `windows-i686` | agent | `wz-linux-amd64` | MinGW cross-compile on Linux. Agent-only. |
| `rpm-amd64` | manager | `wz-linux-amd64` | CentOS 7 manager builder image (glibc 2.17). |
| `rpm-arm64` | manager | `wz-linux-arm64` | CentOS 7 manager builder image. |

Why each Linux arch runs twice: the manager image (CentOS 7) can build a couple of deps the agent image (CentOS 6) can't (newer toolchain), but the agent image's older glibc is the safe baseline for everything else. Both legs build their full dep set; the `consolidate` job picks the agent-image copy when both exist, so we ship glibc-2.12-compatible binaries wherever possible.

We don't build separate `deb` legs because rpm glibc is forward-compatible with deb's.

## Jobs

```
build-externals (matrix, 7 jobs)
       │
       └─► consolidate ──► smoke-build (4 jobs, Linux-only)
```

- **`build-externals`** — each leg seeds `src/external/`, applies `--dependencies` overrides, runs the build, and uploads `externals-<leg>-<target>.tar.gz`.
- **`consolidate`** — downloads every per-leg tarball, merges into the canonical `libraries/{linux,darwin,windows,sources}/` layout, and uploads `externals-all.tar.gz` (the artifact you publish to `packages.wazuh.com/deps/<version>/`).
- **`smoke-build`** — for each of the 4 Linux combinations (amd64/arm64 × agent/manager), pulls `externals-all.tar.gz`, points `make deps RESOURCES_URL=file://…` at the local tree, then runs the real Wazuh build. Confirms the precompiled tarballs you just packed actually get consumed. Emits `::warning::` for any dep that fell back to source compile — that means the binary was packed at a path `src/external/CMakeLists.txt` doesn't expect.

## Output

Per-leg artifacts (`externals-rpm-amd64-agent`, `externals-macos-arm64-agent`, …) are kept 14 days for debugging.

The artifact to publish is `externals-all` → `externals-all.tar.gz`. Its layout matches the S3 directory it gets uploaded into:

```
libraries/
├── linux/{amd64,aarch64}/<dep>.tar.gz   ← precompiled binaries
├── darwin/{amd64,aarch64}/<dep>.tar.gz
├── windows/<dep>.tar.gz                 ← no arch subdir for MinGW
└── sources/<dep>.tar.gz                 ← upstream source snapshots
```

`make deps` walks this exact tree; the path layout is not negotiable. If you change `generate_external.sh`'s `S3_PATH` mapping, you must update `PRECOMPILED_RES` in `src/Makefile` to match (and vice versa).

Smoke build logs (`smoke-build-<target>-<arch>`) are also retained 14 days and are the first place to look when a downstream build starts pulling deps from source unexpectedly.

## Publishing a new DEPS_VERSION — the safe order

1. Open a branch, optionally edit `external_sources.sh` if you're changing a manifest URL.
2. Dispatch the workflow with `dependencies="…"` (or empty for a clean rebuild). **Do not bump `DEPS_VERSION` in this branch.** See the caveat below.
3. Wait for `build-externals`, `consolidate`, and all 4 `smoke-build` jobs to go green.
4. Download `externals-all.tar.gz`. Pick a new `DEPS_VERSION` (the team's convention is `99-<gh-run-id>` or a hand-picked monotonic number). Upload the tarball contents into `s3://…/deps/<new-DEPS_VERSION>/libraries/…`.
5. Open a second PR that bumps `DEPS_VERSION` in `src/Makefile` (and `CPYTHON_PASSTHROUGH_VERSION` in `build_external.sh` if that bump included a new cpython — see below).

## Caveats

### Do not bump `DEPS_VERSION` in the same branch that runs the workflow

`build_external.sh` calls `make deps EXTERNAL_SRC_ONLY=yes` as its first step to seed `src/external/<dep>/`. That call reads `RESOURCES_URL = packages.wazuh.com/deps/$(DEPS_VERSION)/` from `src/Makefile` and downloads every source tarball from there.

If your branch has bumped `DEPS_VERSION` to the version you're trying to *produce*, the seed download 404s and the run fails before it builds anything. Always run with the currently published `DEPS_VERSION`; bump in a follow-up PR after the new tarball is uploaded.

### `CPYTHON_PASSTHROUGH_VERSION` is hand-maintained

cpython has its own build pipeline (`5_builderpackage_embedded-python.yml`); this workflow doesn't compile it. Instead, `build_external.sh` fetches a known-good cpython blob from a pinned version (`CPYTHON_PASSTHROUGH_VERSION`, currently `99-29585`) and re-ships it inside the consolidated tarball.

When the embedded-python pipeline publishes a new cpython, bump `CPYTHON_PASSTHROUGH_VERSION` in `packages/externals/build_external.sh` in the same PR that bumps `DEPS_VERSION` in `src/Makefile`.

### `libbpf-bootstrap` is re-shipped, not rebuilt

`libbpf-bootstrap` is the one dep this workflow does not actually compile. It needs clang ≥ 7 with the BPF backend and Linux UAPI headers ≥ 4.13 (`linux/bpf_perf_event.h`), and the legacy agent builder image (CentOS 6 / Debian wheezy era, glibc 2.12) has neither — a from-source attempt fails with `linux/bpf_perf_event.h: No such file or directory`. Wazuh builds it in a separate centos:7 + clang-15-from-source image (issue #28626) and uploads the result to `packages.wazuh.com`.

`build_external.sh`'s `stage_precompiled` pulls that prebuilt tarball from a pinned known-good deps release (currently `99-29585`), extracts it into `src/external/libbpf-bootstrap/`, and lets the `if(EXISTS …/build/modern.bpf.o)` short-circuit in `src/external/CMakeLists.txt` skip the from-source `ExternalProject_Add`.

Implications:

- **Bumping `libbpf-bootstrap` is out of scope here.** Use the dedicated pipeline, upload the new tarball, then bump the pinned version inside `stage_precompiled` (search for `99-29585` in `build_external.sh`).
- The pinned `99-29585` should be kept in lockstep with `CPYTHON_PASSTHROUGH_VERSION`. Both are independent of `src/Makefile`'s `DEPS_VERSION`.
- This applies to Linux legs only. macOS and Windows agents don't include `libbpf-bootstrap`.

### macOS and Windows are agent-only

There are no manager builder images for darwin or windows. The matrix reflects this; do not add manager entries for those systems.

### Source-rebuild fallbacks are silent

`src/Makefile` line 596 (the precompiled-fetch rule) is `-@ … || true` — a missing precompiled tarball is non-fatal and CMake falls back to source compilation. That means a packing-path bug (binary placed under `libraries/linux/amd64/` when `make deps` looked for `libraries/linux/x86_64/`, say) won't fail `make deps` outright. The smoke-build's "Analyze dependency usage" step is what catches this, by grepping the build log for `Performing build step for '<dep>_external'` / `Building … ext_<dep>.dir/` and emitting `::warning::` for each.

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
