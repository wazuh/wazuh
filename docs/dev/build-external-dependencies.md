# Build External Dependencies

Wazuh 5.x vendors its external dependencies (curl, openssl, rocksdb, ...) as a per-library pool published at `packages.wazuh.com/deps/pool/`. Each library is built once for every platform it ships on, and a build downloads it from the pool instead of rebuilding it. `src/deps.lock.mk` records which pool entry every library uses, and `make deps` reads it. A GitHub Actions workflow builds, tests and publishes the entries the pool does not have yet.

Workflow: `.github/workflows/5_builderpackage_externals.yml`. Lock check: `.github/workflows/5_codequality_externals-lock.yml`. Weekly scan: `.github/workflows/5_codeanalysis_externals-vulns.yml`.

Files under `packages/externals/`:

| File | Purpose |
|------|---------|
| `dependencies.json` | Inventory: version, revision, URL, sha256, archive format, patches, overlay, targets, platforms, binaries, links, CPE, purl and license of every `EXTERNAL_RES` dependency. |
| `deps.py` | Inventory and pool tool, see [deps.py commands](#depspy-commands). |
| `builder-images.json` | Builder image digests of the Linux and Windows legs, runners and Xcode version of the macOS legs. |
| `build_external.sh` | Container-side build of one leg: downloads the dependencies to build from their inventory URL, checks sha256, applies `subdir`, `overlay` and `patches`, takes the rest from the pool, runs `make build-external` and zips the results. Records the toolchain of the leg. |
| `generate_external.sh` | Host-side wrapper: flattens the inventory, runs `build_external.sh` in the builder image (natively on macOS) and packs the result as `pool/<ref>/...` inside `externals-<system>-<arch>-<target>.tar.gz`. |
| `consolidate.sh` | Merges the leg tarballs and the libbpf-bootstrap build into one pool tree and writes `manifest.json` for each ref. |
| `ebpf/build_ebpf.sh` | Builds `libbpf-bootstrap.tar.gz` (`modern.bpf.o` + `libbpf.so`) for amd64, aarch64, arm32, i386 and ppc64le on one x86_64 host, with clang 20 and Zig. |
| `smoke_build.sh` | Builds the agent or manager from source against a local pool tree. |
| `publish_pool.sh` | Uploads the refs of a pool tree to the bucket behind `packages.wazuh.com/deps/pool/`. |
| `pull_builder_image.sh` | Pulls a builder image by the digest pinned in `builder-images.json`. |

`framework/cpython/compile.sh` builds the embedded Python (see [cpython](#cpython)).

## The pool

A pool entry is a ref, `<name>/<version>-<key>`, for example `curl/8.20.0-dd639990`:

```
deps/pool/<name>/<version>-<key>/
├── manifest.json
├── sources/<name>.tar.gz              source tree, after subdir, overlay and patches
├── linux/{amd64,aarch64}/<name>.tar.gz
├── darwin/{amd64,aarch64}/<name>.tar.gz
└── windows/<name>.tar.gz              no arch subdirectory for MinGW
```

`libbpf-bootstrap` has no `sources/` and also ships `linux/{arm32,i386,ppc64le}/`. `cpython` ships `sources/cpython_{x86_64,arm64}.tar.gz` (the built tree with its wheels) and `linux/{amd64,aarch64}/cpython.tar.gz`. An entry with `built: false` (header-only libraries, test frameworks, data) has `sources/` only. An entry with `binaries` has tarballs only for those platforms. A published ref is never modified.

The key is the first 8 hex digits of the sha256 of everything that decides the bytes of the entry, computed without network access (`deps.py key`):

| Input | Source |
|-------|--------|
| Key epoch | `KEY_EPOCH` in `deps.py`; raising it rebuilds every entry. |
| Content fields | `version`, `revision`, `source`, `upstream_sha256`, `snapshot_sha256`, `patches`, `overlay`, `subdir`, `targets`, `platforms`, `format`, `strip` and `built`. `url` is left out: a mirror serving the same sha256 gives the same bytes. License, CPE, purl, notes, `binaries` and the other metadata are not keyed: `binaries` only decides which platform tarballs a manifest must have. |
| Patches and overlay | Text hash of every patch file and of every file of the overlay (CRLF read as LF). |
| Links | The keys of the entries in `links`, so a change in a library rebuilds the ones that link it. |
| Source recipe | `build_external.sh`, `generate_external.sh`, `consolidate.sh`. |
| Build recipe | `src/external/CMakeLists.txt` and the `# deps-recipe` blocks of `src/CMakeLists.txt` and `src/Makefile`. Not applied to `libbpf-bootstrap`. |
| Builders | For each platform of the entry: the image digests of `builder-images.json` for its targets (Linux), the Windows image, or the macOS runners and Xcode version. |
| Own recipe | `cpython`: `framework/cpython/compile.sh`, `framework/cpython/custom/**`, `framework/requirements.txt`, `framework/.python-version` and the `# cpython-recipe` block of `src/Makefile` (plus build recipe and builders). `libbpf-bootstrap`: `ebpf/build_ebpf.sh` and `src/syscheckd/src/ebpf/src/modern.bpf.c`. They replace the source recipe. |

Editing a build recipe or a builder image therefore gives new refs for every library built with it. `deps.py key-paths` prints the repository paths that go into the keys; the path filters of the workflows follow it.

`manifest.json` holds the `inputs_hash` (the full sha256), the inventory entry, the refs of its links, the commit and workflow run that built it, the sha256 of every file, the `toolchain` of each build leg (compilers and tools installed on the fly, which the pinned images do not fix) and the list of unpinned builder images, if any. `cpython` also records its wheels and the sha256 of `framework/requirements.txt`. A manifest is not written, and the run fails, if an entry has no `sources/`, lacks a tarball for a platform of `binaries` (default `platforms`) that the run built, has binaries with `built: false`, or, for `cpython`, ships wheels that differ between architectures or from `framework/requirements.txt`.

## The lock and `make deps`

`src/deps.lock.mk` is generated by `python3 packages/externals/deps.py lock` and holds one line per entry, `DEP_REF_<name> := <name>/<version>-<key>`. Never edit it. `src/Makefile` includes it and downloads every dependency from `$(DEPS_POOL_URL)/<ref>/`:

- `sources/<name>.tar.gz` always, unless the precompiled tarball already extracted the tree.
- `<os>/<arch>/<name>.tar.gz` when `EXTERNAL_SRC_ONLY` is not set. A missing tarball is not an error: CMake builds that dependency from source.
- A missing source tarball fails the download. Transient errors are retried; a 403 or 404 is not.

`DEPS_POOL_URL` defaults to `https://packages.wazuh.com/deps/pool`. For a local or offline build, lay the refs out in a directory and point it there:

```bash
python3 packages/externals/deps.py mirror --dest /tmp/pool --target manager --platform linux/amd64
make -C src deps TARGET=manager DEPS_POOL_URL=file:///tmp/pool
```

`mirror` copies the refs the target needs from the pool (only `sources/` and the given platform) and checks every file against its manifest. `--local DIR` takes the refs from a local pool tree first, `--without cpython` leaves entries out, `--target` accepts `agent`, `manager` and `winagent`. It stops if the lock is stale.

`make deps TARGET=agent EXTERNAL_SRC_ONLY=yes` on Linux cannot fetch `libbpf-bootstrap`, which has no sources in the pool. No build uses that combination.

## Bumping a dependency

1. Edit `packages/externals/dependencies.json` (version, revision, `url`, sha256 of the downloaded archive, patches). For `libbpf-bootstrap` the revision must match `LIBBPF_TAG` in `ebpf/build_ebpf.sh`, for `cpython` the version must match `framework/.python-version`.
2. Run `deps.py check`, `deps.py readme` and `deps.py lock`, and commit `dependencies.json`, `README.md` and `src/deps.lock.mk`.
3. Open the PR. The build workflow runs on pull requests that touch a path of the keys. `deps.py plan` lists the entries whose ref the pool does not have, and only those are built; it fails if a published ref was built from other inputs. A change that gives no new ref, such as a license fix, builds nothing.
4. When `pool`, `smoke-build` and the rest are green, approve the `deps-publish` environment on the `publish` job. Whoever approves reviews the whole diff of the PR at that SHA, workflow included. `publish` is skipped until the `DEPS_POOL_PUBLISH` repository variable is `true`.
5. Merge after the refs are published. The lock check (`deps.py pool-check`) stays red until every ref of the lock is in the pool with the inputs it was keyed on; re-run it after publishing.

## Workflow

Triggers: pull requests that touch a path of the keys (and the workflow itself), and manual dispatch. There are no inputs. To run it from the CLI: `gh workflow run 5_builderpackage_externals.yml --ref <branch>`. To re-run a failed leg, use **Re-run failed jobs**.

```
check ─► build-externals (7 legs) ─┐
  │                                ├─► consolidate ─► cpython (2) ─► pool ─► smoke-build (5) ─► publish ─► verify
  └────► build-ebpf ───────────────┘
```

| Job | What it does |
|-----|--------------|
| `check` | `deps.py lock --check`, then `deps.py plan`. Sets which of the legs, libbpf-bootstrap and cpython have something to build. If no ref is missing, nothing else runs. |
| `build-externals` | Runs only if some entry other than `cpython` and `libbpf-bootstrap` is missing. Pulls the pinned builder image (macOS: selects the pinned Xcode), then `generate_external.sh` with `DEPS_BUILD` set to the missing entries. Entries not in `DEPS_BUILD` are taken from the pool by `make`. Uploads `externals-<leg>-<target>`. |
| `build-ebpf` | Runs if `libbpf-bootstrap` is missing. Installs clang 20 and the Zig version pinned in `build_ebpf.sh`, builds every Linux arch, records the toolchain and uploads `libbpf-bootstrap`. |
| `consolidate` | `consolidate.sh`: merges the legs into one pool tree and writes the manifests. Uploads `externals-all`. |
| `cpython` | Runs if `cpython` is missing, see [cpython](#cpython). Uploads `cpython-<arch>`. |
| `pool` | Merges `externals-all` and the `cpython-*` refs, writes the `cpython` manifest (`deps.py manifest --only cpython`) and uploads `pool-new`: every new ref, with its manifest. |
| `smoke-build` | Agent and manager on amd64 and arm64 in their builder images, and the Windows agent in `compile_windows_agent`. `deps.py mirror --local` lays out `pool-new` over the published pool, `smoke_build.sh` runs `make deps DEPS_POOL_URL=file://...` and builds from source. The analysis step warns for any dependency recompiled from source, which means a tarball was packed at a path `src/external/CMakeLists.txt` does not expect. The Windows leg catches host tools shipped under `windows/` (for example `flatc`) built against a newer glibc than the consumer image. |
| `publish` | Environment `deps-publish`. `deps.py verify --local pool-new/pool --pool file://...` checks every file against its manifest, then `publish_pool.sh` uploads. |
| `verify` | `deps.py verify --local pool-new/pool` reads every published ref back through `packages.wazuh.com`. |

Legs of `build-externals`:

| Leg | Target | Runner | Notes |
|-----|--------|--------|-------|
| `rpm-amd64`, `rpm-arm64` | agent | `wz-linux-amd64`, `wz-linux-arm64` | CentOS 6 agent builder image (glibc 2.12 baseline). |
| `macos-intel64`, `macos-arm64` | agent | `macos-14-large`, `macos-14` | Native build with the Xcode pinned in `builder-images.json`. |
| `windows-i686` | agent | `wz-linux-amd64` | MinGW cross-compile in `compile_windows_agent`. |
| `rpm-amd64`, `rpm-arm64` | manager | `wz-linux-amd64`, `wz-linux-arm64` | CentOS 7 manager builder image (glibc 2.17). |

The manager image builds a few libraries the agent image cannot (newer toolchain). Both Linux legs build the agent set, and `consolidate.sh` keeps the agent copy where both produced a tarball, so the binaries run with glibc 2.12. A leg packs a platform tarball only for a library that produced a compiled file (`.a`, `.so`, `.lib`, `.dylib`). Sources are the same on every leg and the first copy is kept. There are no deb legs: rpm glibc is forward-compatible.

Builder images are pinned by digest in `builder-images.json` and pulled by `pull_builder_image.sh`, which tags them with the first 12 digits (`BUILDER_TAG`). The toolchain that is not pinned (packages installed by `build_external.sh`, compiler versions, macOS runner image) is recorded in each `manifest.json`. Artifacts go to the CI internal S3 bucket (`upload_s3_artifact`), not to GitHub Actions artifacts: `externals-<leg>-<target>`, `libbpf-bootstrap`, `externals-all`, `cpython-<arch>`, `pool-new` and `smoke-build-<target>-<arch>`.

### Publishing

`publish_pool.sh <pool_dir> <bucket>` is idempotent per ref. A ref whose published manifest has the same `inputs_hash` is skipped, and one with another `inputs_hash` is an error. Every file is written with `--if-none-match '*'` and `manifest.json` goes last, so a ref without it is incomplete and the next run completes it. If a key exists with other bytes (builds are not byte-reproducible), the existing bytes stay and their sha256 replaces this run's in the uploaded manifest. It needs bash 4.4, python3, an AWS CLI with `put-object --if-none-match` and `s3:ListBucket` on the bucket, limited to the `deps/pool/` prefix.

The `publish` job runs the workflow YAML of the PR, so the only barrier is the role: its trust policy must accept only the OIDC token of the `deps-publish` environment (`sub` = `repo:wazuh/wazuh:environment:deps-publish`, `aud` = `sts.amazonaws.com`), and its permissions must stay limited to `deps/pool/*`. A role trusted by the repository or by a branch would let any PR publish without approval.

To publish by hand, download the `pool-new` artifact, extract it, run `deps.py verify --local pool-new/pool --pool file://$PWD/pool-new/pool`, then `publish_pool.sh pool-new/pool <bucket>` and `deps.py verify --local pool-new/pool`.

### cpython

`cpython` is built in the same workflow, after `consolidate`, for linux/amd64 and linux/aarch64 in the manager image. `deps.py mirror --without cpython` lays out the manager's other refs (those of this run first, then the pool), and `compile.sh --build-cpython --build-deps` builds the interpreter against them (`DEPS_POOL_URL=file:///deps/pool`), downloads the wheels of `framework/requirements.txt` and installs the interpreter and the wheels next to `libwazuhext`. The `pool` job writes its manifest, which checks the wheels of both architectures against `framework/requirements.txt`. A wheel bump therefore changes `requirements.txt`, which is part of the key, and rebuilds only cpython. Manager only.

### libbpf-bootstrap

It needs clang 7 or later with the BPF backend and Linux headers 4.13 or later, which the agent builder images lack, so it is not built by the legs and has no from-source fallback in `src/external/CMakeLists.txt`. `build_ebpf.sh` compiles `modern.bpf.o` from `src/syscheckd/src/ebpf/src/modern.bpf.c` and cross-compiles libbpf with Zig against glibc 2.17 (2.19 on ppc64le). Versions are pinned at the top of the script. The output is reproducible. To build it locally on `ubuntu:24.04` with `libelf-dev zlib1g-dev`, `apt.llvm.org/llvm.sh 20` and the pinned Zig: `bash packages/externals/ebpf/build_ebpf.sh` (writes `output/<arch>/libbpf-bootstrap.tar.gz`).

## deps.py commands

`python3 packages/externals/deps.py <command> --help` lists the options.

| Command | Purpose | Network |
|---------|---------|---------|
| `check` | Schema, links, pins and names against `make print-EXTERNAL_RES` for each target. | no |
| `flatten` | Inventory as bash arrays for `build_external.sh`. | no |
| `readme` | Rewrites the dependency table of `README.md`; `--check` fails if it differs. | no |
| `sbom` | CycloneDX SBOM; `--target`, `--manifest` (a 4.x set manifest). | no |
| `lock` | Writes `src/deps.lock.mk`; `--check` fails if stale. | no |
| `key [NAME...]` | Prints `<ref> <inputs sha256>`. | no |
| `key-paths` | Paths that go into the keys. | no |
| `builder-image <path>...` | A value of `builder-images.json`, for example `linux manager amd64`. | no |
| `plan` | Entries whose ref is not in the pool. | yes |
| `pool-check` | Every ref of the lock is in the pool, built from the inputs it is keyed on. | yes |
| `manifest --pool DIR` | Writes the `manifest.json` of every ref in a pool tree. | no |
| `mirror --dest DIR` | Lays out the refs a target needs. | yes |
| `verify --local DIR` | Compares the refs of a local pool tree with what `--pool` serves, file by file. | yes |

## Dependency matrix

Which dependency each platform and target builds and links, and what the pool holds for it. The download set per target lives in `EXTERNAL_RES` (`src/Makefile`) and the build and link guards in `src/external/CMakeLists.txt`. A dependency is downloaded for the targets that compile it, with three exceptions downloaded more widely for their headers: bzip2 (every target), audit-userspace and procps (every Linux target, manager included, because the unit-test wrappers in `src/unit_tests/wrappers/externals/` include `<libaudit.h>` and `procps/readproc.h`), and the test frameworks (every target).

Legend: x used, - not used. Targets: **La** Linux agent, **Lm** Linux manager, **Ma** macOS agent, **Wa** Windows agent (MinGW). Pool column: `bin` is `sources/` plus platform tarballs, `src` is `sources/` only (`built: false`).

| Dependency | La | Lm | Ma | Wa | Pool |
|------------|----|----|----|----|------|
| cJSON, openssl, zlib, sqlite, libyaml, curl, libpcre2, flatbuffers, zstd | x | x | x | x | bin (flatbuffers also ships `flatc`; zlib bundles minizip on non-Windows) |
| bzip2 | x | x | x | x | bin on linux and darwin only: Windows needs the header (`shared.h` includes `bzlib.h`) but does not link it |
| nlohmann, jwt-cpp, rapidjson | x | x | x | x | src, header-only |
| googletest, benchmark | x | x | x | x | src; compiled only when `UNIT_TEST` or `WAZUH_ENGINE_TEST` is set, but downloaded always because `make deps` does not get `TEST=1` and the unit-test CI shares the bundle |
| audit-userspace, procps | x | - | - | - | bin; the manager uses only the headers |
| libdb, popt, lua, rpm, dbus | x | - | - | - | bin (popt and lua are rpm dependencies) |
| libbpf-bootstrap | x | - | - | - | linux bin only, built by `build_ebpf.sh`, no `sources/` |
| libplist | - | - | x | - | bin |
| cpython | - | x | - | - | bin, see [cpython](#cpython) |
| libffi, jemalloc, rocksdb, simdjson, abseil-cpp, re2, spdlog, yaml-cpp, pugixml, libmaxminddb, protobuf, date, fmt, llhttp | - | x | - | - | bin (re2 needs abseil, date needs curl, libffi serves cpython) |
| asio, expected-lite, restinio, RxCpp, taskflow, concurrentqueue, fast_float, cpp-httplib | - | x | - | - | src, header-only |
| geo_db, tzdata | - | x | - | - | src, data (MaxMind GeoLite2 snapshot, IANA tz) |

Header-only libraries and data carry no compiled file, so they exist only under `sources/`. minizip lives in the zlib tree and is built on the non-Windows legs, so it ships inside `zlib.tar.gz`.

## Inventory fields

`deps.py check` is the only definition of the schema; this is what each field means. Entries are sorted by `name`.

| Field | Meaning |
|-------|---------|
| `name` | The name in `EXTERNAL_RES` and the directory under `src/external/`. |
| `version` | Public release whose code the content matches, verified by content: build files often carry a stale version. Failing that (rapidjson, date), the closest earlier release; geo_db, which is data, carries its date. |
| `revision` | Exact upstream tag or commit; for procps, which has no tags for 3.2.x, the release tarball name, and for geo_db the CTI export it came from. |
| `source` | `upstream` (the project's own release archive) or `snapshot` (a published tarball is the source; only `geo_db`, which is data, uses it). |
| `url` | Download URL. Placeholders: `{version}`, `{version_us}` (dots to underscores), `{version_dash}` (dots to dashes), `{version_concat}` (sqlite's form, `3.51.1` to `3510100`) and `{revision}`. |
| `upstream_sha256` / `snapshot_sha256` | sha256 of the downloaded file, required by `source`: `curl -fsSL <url> \| sha256sum`. |
| `format`, `strip` | Archive format (`tar.gz`, `tar.bz2`, `tar.xz`, `zip`, or `file` for a single file) and the leading directories to strip. |
| `subdir` | Optional. Only this subdirectory of the extracted archive is kept (after `strip`); procps uses `proc`. A relative path without `..`. |
| `overlay` | Optional. Name of a directory under `packages/externals/overlay/`, copied over the tree. It must exist and hold at least one file. |
| `patches` | Files under `packages/externals/patches/`, applied in order with `git apply -p1`. |
| `targets`, `platforms` | `agent`/`manager` and `linux`/`darwin`/`windows`; `check` compares them with `make print-EXTERNAL_RES` for each target and platform. |
| `built` | Optional, default `true`. `false`: no binaries, the pool entry holds `sources/` only. |
| `binaries` | Optional. Subset of `platforms` that get a tarball; the default is all of them. bzip2 uses `darwin`, `linux`. |
| `links` | Optional. Other entries this one links, which must match the `DEPENDS` of its `ExternalProject_Add` in `src/external/CMakeLists.txt` (for cpython, the manager's `WAZUHEXT_WHOLE_LIBS`). Their keys go into this key. No cycles. |
| `cpe` | Versionless CPE 2.3 (`cpe:2.3:a:<vendor>:<product>:*:...`), a list of them, or `null` together with `scan: false`. The version always comes from `version`. |
| `purl` | `pkg:github/<owner>/<repo>@<revision>` or `pkg:generic/<name>@<version>`, with a `/` in the version percent-encoded. |
| `scan`, `reason` | `scan: false` needs a `reason`, usually "no CPE in NVD". |
| `license`, `author`, `homepage` | Columns of the README table. |
| `notes`, `prebuilt` | Informational; the build does not read them. |

`build_external.sh` applies them in this order: extract, `subdir`, `overlay`, `patches`.

## Dependencies with Wazuh changes

Every dependency is built from its upstream release. What Wazuh changes lives in the repository, in one of four forms; pick the smallest that expresses the change.

**Build option.** A flag set in the dependency's rule in `src/external/CMakeLists.txt`: lua builds with an explicit `CFLAGS` without `-march=native`, libplist configures with `--without-cython`, libpcre2 builds with `PROGRAMS=` (library and headers only; its test programs do not link with MinGW). To add one, edit the `BUILD_COMMAND`, `CONFIGURE_COMMAND` or `CMAKE_ARGS` of the rule; to remove it, delete the flag. The inventory does not change, but the build recipe is keyed, so every library built with that file gets a new ref.

**Overlay.** A file of our own that replaces or completes one of upstream: rpm and popt ship their `CMakeLists.txt` this way. Put it at `packages/externals/overlay/<dir>/<path>` and set `overlay` to `<dir>` in the entry; the build copies the directory over the extracted tree. To remove it, delete the directory and the field.

**Patch.** A change to upstream code, in `packages/externals/patches/<lib>/NNNN-<name>.patch`, listed in `patches`: RxCpp, rpm (ndb), procps and date. The file is relative to the tree after `subdir`, and its header must carry `Why:`, `Upstream:` and `Remove when:` with a value each, before the first `diff`. To remove it, delete the file and its `patches` item, typically when `Remove when:` holds, for instance after a bump to a release that includes the change.

**Nothing.** flatbuffers, bzip2, audit-userspace and libyaml build as upstream ships them.

Only `geo_db`, which is data, stays a `source: snapshot`. `deps.py check` requires a snapshot to point under `packages.wazuh.com/deps/`, where its published file lives, and a snapshot is never the way to carry a code change. When you bump a dependency, check that its overlay and patches still apply; `build_external.sh` fails the leg if a patch does not.

## Pull request checks

`5_codequality_externals-lock.yml` runs on pull requests that touch the key paths, `packages/externals/**`, `README.md` or the workflow itself:

1. The `deps.py` tests (`packages/externals/tests`), with MinGW installed so the Windows list is evaluated.
2. `deps.py check`.
3. `deps.py readme --check`: the README table must be the one generated from the inventory.
4. `deps.py lock --check`: `src/deps.lock.mk` must be the one the inventory generates.
5. `deps.py pool-check`: every ref of the lock must be published with the inputs it was keyed on.

Step 5 is what keeps a bump from merging before its refs exist.

## Weekly vulnerability scan

`5_codeanalysis_externals-vulns.yml` runs on Mondays at 12:17 UTC, after the daily Grype database is published, and on demand, from the default branch. The weekly operational report reads its results on Tuesday at 06:00 UTC; if the Monday run fails, dispatch it again before then. For every versioned branch (`main`, `5.0.x`, `4.14.x`, ...) with commits in the last 120 days, it builds the SBOM of the dependencies `make deps TARGET=manager` downloads (`deps.py sbom --target manager`, which also counts header-only and test dependencies, plus the wheels of `framework/requirements.txt`): from the branch's `dependencies.json`, or, on branches without one (4.x), from the `manifest.json` of the set its `DEPS_VERSION` points at; a branch whose set has no manifest is skipped with a notice. Grype scans it and the SARIF goes to code scanning under the category `externals-vulns-<branch>`. Agent-only dependencies are not scanned.

Grype applies no verdicts here: CVEs that do not affect a dependency are recorded and discounted by the weekly report that reads these results. A CVE that is fixed in a later version is not a verdict: bump the dependency instead.

## Caveats

### Source-rebuild fallbacks are silent

The precompiled-fetch rules in `src/Makefile` (`external-precompiled/%.tar.gz` and its cpython counterpart) are `-@ ... || true`: a missing precompiled tarball is non-fatal and CMake falls back to source compilation. A packing-path bug (a binary placed under `linux/amd64/` when `make deps` looked for `linux/aarch64/`, say) therefore does not fail `make deps`. The smoke-build analysis step catches it by grepping the build log for `Performing build step for '<dep>_external'` and `Building ... ext_<dep>.dir/`. Treat any smoke-build warning as a blocker.

### macOS and Windows are agent-only

There are no manager builder images for darwin or windows. The matrix reflects this; do not add manager entries for those systems.

### Debugging a leg

Use **Re-run failed jobs** rather than dispatching a new run. To reproduce a leg locally, pull the builder image with `pull_builder_image.sh` and run `packages/externals/generate_external.sh --system rpm --architecture amd64 --target agent --tag <tag> --verbose` from `packages/`. `DEPS_BUILD="curl openssl"` restricts the build to those entries and takes the rest from the pool (`DEPS_POOL_URL` overrides it); empty builds everything. The refs come out under `packages/output_externals/pool/`.

### 4.x branches

4.x branches keep `DEPS_VERSION` in `src/Makefile` and the classic numbered sets at `packages.wazuh.com/deps/<DEPS_VERSION>/` (`libraries/` plus, for newer sets, a `manifest.json`). None of the above applies to them except the weekly scan.

## Related

- [Package generation](package-generation.md): `generate_package.sh`, the script that turns built sources and deps into shipped `.rpm`/`.deb`.
- `src/Makefile`: `DEPS_POOL_URL`, `dep_url`, `PRECOMPILED_RES`, `EXTERNAL_RES`.
- `src/external/CMakeLists.txt`: the consumer side; decides which deps short-circuit to precompiled archives and which build from source.
