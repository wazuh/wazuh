#!/bin/bash
#
# Wazuh external dependency builder (container-side).
#
# Runs inside one of the package builder Docker images (e.g.
# packages/debs/amd64/manager:<tag>). Driven by
# packages/externals/generate_external.sh on the host.
#
# Inputs (env vars set by the host script):
#   BUILD_TARGET        agent | manager        (passed to `make TARGET=`)
#   ARCHITECTURE_TARGET amd64 | arm64 | ...    (used in artifact filenames)
#   SYSTEM              deb | rpm | macos | windows  (used in artifact filenames)
#   DEPS_ENV            packages/externals/dependencies.json flattened by
#                       `deps.py flatten` (bash arrays EXT_URL, EXT_SHA256, ...)
#   JOBS                parallel build jobs (defaults to nproc)
#   WAZUH_VERBOSE       "yes" enables `set -x`
#
# Sources (location varies by mode):
#   ${WAZUH_SRC}                  the working tree (default /wazuh-local-src
#                                 — the path the Linux/Windows builder
#                                 containers see; macOS native runs override
#                                 it to the actual checkout path).
#   ${WAZUH_SRC}/packages/externals/patches/      Wazuh changes to upstream sources
#
# Output:
#   ${ARTIFACTS_DIR}/<dep>_src.zip
#   ${ARTIFACTS_DIR}/<dep>_<system>_<architecture>.zip
#   (defaults to /var/local/wazuh/external_artifacts inside containers; on
#    macOS native runs the host script overrides it to a path on the runner.)

set -e

# macOS ships bash 3.2 which lacks associative arrays (declare -A).
# Re-exec with Homebrew bash >=4 when necessary.
if [[ "${BASH_VERSINFO[0]}" -lt 4 && "$(uname -s)" == "Darwin" ]]; then
    brew_prefix="$(brew --prefix 2>/dev/null)"
    brew_bash="${brew_prefix}/bin/bash"
    if [[ -x "$brew_bash" ]]; then
        exec "$brew_bash" "$0" "$@"
    fi
    echo "[build_external] ERROR: bash >=4 required on macOS; install with: brew install bash" >&2
    exit 1
fi

WAZUH_SRC="${WAZUH_SRC:-/wazuh-local-src}"
SRC_DIR="${WAZUH_SRC}/src"
EXTERNAL_DIR="${SRC_DIR}/external"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-/var/local/wazuh/external_artifacts}"
DOWNLOAD_DIR="${DOWNLOAD_DIR:-/tmp/external_upstream}"

JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)}"

if [ "${WAZUH_VERBOSE}" = "yes" ]; then
    set -x
fi

mkdir -p "${ARTIFACTS_DIR}" "${DOWNLOAD_DIR}"

log() { echo "[external] $*"; }
err() { echo "[external][ERROR] $*" >&2; }

# Source-of-truth for any blob we re-ship rather than build here (currently
# cpython, see the cpython pass-through block below). Reading from src/Makefile keeps the URLs in
# lockstep with what `make deps` would download for the same source tree,
# which means DEPS_VERSION must point at an *existing* publish at the time
# this workflow runs. Never bump DEPS_VERSION in the same branch that
# dispatches this workflow — do the bump in a follow-up PR after the new
# tarball is uploaded. See docs/dev/build-external-dependencies.md.
DEPS_VERSION="$(sed -n 's/^DEPS_VERSION[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*/\1/p' "${SRC_DIR}/Makefile" | head -n1)"
if [ -z "${DEPS_VERSION}" ]; then
    err "could not extract DEPS_VERSION from ${SRC_DIR}/Makefile"
    exit 1
fi
log "DEPS_VERSION (from src/Makefile): ${DEPS_VERSION}"

# Runtime tooling not always present in the package builder images:
#   - zip/unzip: write per-dep snapshot zips and extract .zip upstream tarballs.
#   - clang: required by libbpf-bootstrap's FindBpfObject.cmake to compile
#     eBPF objects (`-target bpf`). gcc has no BPF backend. On wheezy/centos:6
#     the distro clang is too old for BPF (3.0/3.4); libbpf rebuild will fail
#     there, but everything else still installs.
#   - libelf-dev / elfutils-libelf-devel: libbpf-bootstrap requires libelf.h.
#   - pkg-config: libbpf's Makefile uses pkg-config to find libelf.
#   - libexpat1-dev / expat-devel: dbus configure needs expat (centos:6's
#     expat-devel is missing the .pc file — see EXPAT_CFLAGS workaround later).
#   - perl-IPC-Cmd: openssl 3.x Configure requires it (yum-only; apt's perl
#     ships IPC::Cmd in core).
#   - perl-Time-Piece: openssl ≥ 3.5.x Makefile.in uses Time::Piece for
#     build-date stamping. centos:7's minimal perl install omits it
#     (apt's perl ships Time::Piece in core).
# Per-package install: a single missing candidate would otherwise abort the
# whole apt/yum transaction. Each package fails independently.
if command -v apt-get >/dev/null 2>&1; then
    log "refreshing apt indices and installing tooling"
    apt-get update -y >/dev/null 2>&1 || apt-get update -y || true
    # --allow-unauthenticated handles archive repos with unsigned Releases.
    for _pkg in zip unzip clang libelf-dev pkg-config libexpat1-dev; do
        apt-get install -y --allow-unauthenticated "${_pkg}" >/dev/null 2>&1 || \
        apt-get install -y --allow-unauthenticated "${_pkg}" || \
        err "apt-get install ${_pkg} failed; downstream build may fail"
    done
elif command -v yum >/dev/null 2>&1; then
    log "installing tooling via yum (per-package)"
    for _pkg in zip unzip clang elfutils-libelf-devel pkgconfig perl-IPC-Cmd perl-Time-Piece expat-devel; do
        yum install -y "${_pkg}" >/dev/null 2>&1 || \
        yum install -y "${_pkg}" || \
        err "yum install ${_pkg} failed; downstream build may fail"
    done
elif command -v brew >/dev/null 2>&1; then
    # macOS: zip/unzip in base system. pkg-config is the one reliably absent.
    # libtool/autoconf/automake are needed by libplist's autoreconf step. On
    # macos-13 (Intel) brew lives under /usr/local and aclocal already searches
    # there; on macos-14 (arm64) brew is /opt/homebrew so AC_PROG_LIBTOOL goes
    # missing without ACLOCAL_PATH pointing at the brew aclocal dir.
    log "installing tooling via brew"
    for _pkg in pkg-config libtool autoconf automake; do
        brew install "${_pkg}" >/dev/null 2>&1 || brew install "${_pkg}" || \
        err "brew install ${_pkg} failed; downstream build may fail"
    done
    _brew_prefix="$(brew --prefix 2>/dev/null || true)"
    if [ -n "${_brew_prefix}" ] && [ -d "${_brew_prefix}/share/aclocal" ]; then
        export ACLOCAL_PATH="${_brew_prefix}/share/aclocal:${ACLOCAL_PATH:-}"
    fi
fi

# centos:6's expat-devel ships without expat.pc, so dbus configure's
# `pkg-config expat` lookup fails. Provide CFLAGS/LIBS directly when we
# detect the headers are present but pkg-config can't find them. Harmless
# on images where pkg-config does work — autoconf prefers explicit env
# vars over re-querying pkg-config.
if [ -f /usr/include/expat.h ] && ! pkg-config --exists expat 2>/dev/null; then
    log "expat headers present but pkg-config can't find them; setting EXPAT_CFLAGS/LIBS"
    export EXPAT_CFLAGS="-I/usr/include"
    export EXPAT_LIBS="-lexpat"
fi

if [ ! -f "${DEPS_ENV:-}" ]; then
    err "DEPS_ENV '${DEPS_ENV:-}' not found (generate_external.sh writes it with deps.py flatten)"
    exit 1
fi
# shellcheck disable=SC1090
source "${DEPS_ENV}"

# Download $1 to $2, retrying a few times.
download() {
    local url="$1" dest="$2"
    local attempts=4 delay=5
    for i in $(seq 1 ${attempts}); do
        if curl --fail --location --show-error --silent \
                --connect-timeout 20 --max-time 600 \
                --output "${dest}" "${url}"; then
            return 0
        fi
        err "download failed (attempt ${i}/${attempts}): ${url}"
        sleep ${delay}
        delay=$((delay * 2))
    done
    return 1
}

# Extract $1 (with format $2) into $3, stripping $4 leading components.
extract() {
    local archive="$1" format="$2" dest="$3" strip="$4"
    mkdir -p "${dest}"
    case "${format}" in
        tar.gz|tgz)
            tar -xzf "${archive}" -C "${dest}" --strip-components="${strip}"
            ;;
        tar.bz2)
            tar -xjf "${archive}" -C "${dest}" --strip-components="${strip}"
            ;;
        tar.xz)
            tar -xJf "${archive}" -C "${dest}" --strip-components="${strip}"
            ;;
        file)
            cp "${archive}" "${dest}/"
            ;;
        zip)
            local tmp
            tmp="$(mktemp -d)"
            unzip -q "${archive}" -d "${tmp}"
            # Mimic --strip-components for zip: skip ${strip} levels.
            local inner="${tmp}"
            for _ in $(seq 1 "${strip}"); do
                inner="$(find "${inner}" -mindepth 1 -maxdepth 1 -type d | head -n1)"
                [ -z "${inner}" ] && break
            done
            cp -a "${inner}/." "${dest}/"
            rm -rf "${tmp}"
            ;;
        *)
            err "unknown archive format: ${format}"
            return 1
            ;;
    esac
}

# True when dependency $1 is built on this leg's platform.
on_leg() {
    case " ${EXT_PLATFORMS[$1]:-} " in
        *" ${LEG_PLATFORM} "*) return 0 ;;
    esac
    return 1
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Download dependency $1 from its inventory URL, check its sha256, apply its
# patches and install it as src/external/<target_dir>/. Any failure is fatal:
# a leg never falls back to another source.
fetch_dep() {
    local name="$1"
    local url="${EXT_URL[$name]}" format="${EXT_FORMAT[$name]}" strip="${EXT_STRIP[$name]}"
    local target_dir="${EXT_TARGET[$name]}"
    # Keep the upstream file name: the `file` format installs it as is.
    local archive="${DOWNLOAD_DIR}/${name}/${url##*/}"
    local staging="${DOWNLOAD_DIR}/tree/${target_dir}"

    log "fetching ${name} ${EXT_VERSION[$name]} from ${url}"
    mkdir -p "${DOWNLOAD_DIR}/${name}"
    download "${url}" "${archive}" || { err "failed to download ${name} from ${url}"; return 1; }
    local got
    got="$(sha256_of "${archive}")"
    if [ "${got}" != "${EXT_SHA256[$name]}" ]; then
        err "sha256 mismatch for ${name}: expected ${EXT_SHA256[$name]}, got ${got} (${url})"
        return 1
    fi

    rm -rf "${staging}"
    extract "${archive}" "${format}" "${staging}" "${strip}" || return 1
    # Applied outside the repository: inside a work tree `git apply` resolves
    # paths from its top level and silently skips those outside the cwd.
    local patch
    for patch in ${EXT_PATCHES[$name]}; do
        log "applying ${patch} to ${name}"
        if ! (cd "${staging}" && git apply -p1 --whitespace=nowarn "${WAZUH_SRC}/packages/externals/patches/${patch}"); then
            err "patch ${patch} does not apply to ${name} ${EXT_VERSION[$name]}"
            return 1
        fi
    done

    rm -rf "${EXTERNAL_DIR:?}/${target_dir}"
    mv "${staging}" "${EXTERNAL_DIR}/${target_dir}"
}

# Snapshot src/external/<dep>/ as <dep>_src.zip (pre-build).
snapshot_source() {
    local name="$1"
    local target_dir="${EXT_TARGET[$name]}"
    local out="${ARTIFACTS_DIR}/${name}_src.zip"
    if [ ! -d "${EXTERNAL_DIR}/${target_dir}" ]; then
        log "no source dir for '${name}' (${target_dir}); skipping src snapshot"
        return 0
    fi
    log "snapshot src: ${name} -> ${out}"
    (cd "${EXTERNAL_DIR}" && zip -rq "${out}" "${target_dir}")
}

# Snapshot src/external/<dep>/ post-build (includes built .a/.so/.lib).
snapshot_built() {
    local name="$1"
    local target_dir="${EXT_TARGET[$name]}"
    local out="${ARTIFACTS_DIR}/${name}_${SYSTEM}_${ARCHITECTURE_TARGET}.zip"
    if [ ! -d "${EXTERNAL_DIR}/${target_dir}" ]; then
        log "no source dir for '${name}' (${target_dir}); skipping built snapshot"
        return 0
    fi
    log "snapshot built: ${name} -> ${out}"
    (cd "${EXTERNAL_DIR}" && zip -rq "${out}" "${target_dir}")
}

# Print the dependency list make resolves for a given TARGET (agent / manager /
# winagent), reading it straight from src/Makefile's `print-%` helper. make
# evaluates the ifeq/${TARGET}/${uname_S} logic, so it stays the single source
# of truth: an awk parser here cannot evaluate those conditionals and silently
# drifts whenever the EXTERNAL_RES blocks are restructured (e.g. it would miss
# every per-OS agent dep and bzip2). `$(CPYTHON)` and any other make variable
# are expanded for free.
collect_deps_for_target() {
    local target="$1"
    make -s -C "${SRC_DIR}" print-EXTERNAL_RES TARGET="${target}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

log "BUILD_TARGET=${BUILD_TARGET} SYSTEM=${SYSTEM} ARCH=${ARCHITECTURE_TARGET} JOBS=${JOBS}"

# Map our (system, build-target) tuple to the value src/Makefile expects in
# its TARGET variable. Windows agent uses TARGET=winagent (not 'agent') —
# that flag turns on MinGW cross-compile and filters Linux-only deps from
# the dep list (see src/Makefile:462-465). Linux/macOS pass through.
if [ "${SYSTEM}" = "windows" ]; then
    MAKE_TARGET="winagent"
else
    MAKE_TARGET="${BUILD_TARGET}"
fi
case "${SYSTEM}" in
    deb|rpm) LEG_PLATFORM="linux" ;;
    macos)   LEG_PLATFORM="darwin" ;;
    *)       LEG_PLATFORM="${SYSTEM}" ;;
esac

# Determine the dep set this leg cares about up-front. Use MAKE_TARGET (not
# BUILD_TARGET) so the windows leg resolves the winagent dep set rather than the
# agent one, which would wrongly pull in the Linux-only deps.
DEPS_FOR_LEG="$(collect_deps_for_target "${MAKE_TARGET}")"
log "deps for this leg: ${DEPS_FOR_LEG}"

log "removing stale tar/tar.gz intermediates under src/external/"
find "${EXTERNAL_DIR}" -maxdepth 1 \( -name '*.tar' -o -name '*.tar.gz' \) -type f -delete 2>/dev/null || true

log "pre-cleaning src/external/<dep>/ dirs for clean tar extract"
for name in ${DEPS_FOR_LEG}; do
    rm -rf "${EXTERNAL_DIR:?}/${name}"
done

# cpython and libbpf-bootstrap are built by their own pipelines, and the
# other prerequisites of `make deps` (shared modules, indexer templates, ...)
# are not in the inventory: let make fetch them exactly as `make deps` does.
make_goals=""
for var in SHARED_TAR INDEXER_TEMPLATE_FILES WCS_FLAT_FILES CREDENTIALS_LIB_FILES; do
    make_goals="${make_goals} $(make -s -C "${SRC_DIR}" "print-${var}" TARGET="${MAKE_TARGET}")"
done
for name in ${DEPS_FOR_LEG}; do
    case "${name}" in
        cpython|libbpf-bootstrap) make_goals="${make_goals} external/${name}.tar.gz" ;;
        *)
            if on_leg "${name}"; then
                fetch_dep "${name}" || exit 1
            fi
            ;;
    esac
done
log "fetching from deps/${DEPS_VERSION} through make:${make_goals}"
# shellcheck disable=SC2086
make -C "${SRC_DIR}" EXTERNAL_SRC_ONLY=yes TARGET="${MAKE_TARGET}" ${make_goals}

# Some cached source tarballs at packages.wazuh.com (notably the openssl one)
# were originally packed with bsdtar on macOS, so every file has a
# `com.apple.provenance` xattr and the archive carries an AppleDouble `._<file>`
# sibling for each. GNU tar on the Linux runners extracts those AppleDouble
# files as regular files; without this step they flow through snapshot_src and
# snapshot_built into every per-leg tarball (6149 `._*` entries in the openssl
# leg output, confirmed by raw byte-walk of the cached tarball at
# `packages.wazuh.com/deps/99-29585/libraries/sources/openssl.tar.gz`).
log "stripping AppleDouble (._*) files from extracted source trees"
find "${SRC_DIR}/external" -name '._*' -delete

# sqlite's autoconf tarball ships a `VERSION` text file (just the version
# string, e.g. "3.53.1"). src/external/CMakeLists.txt adds external/sqlite/
# itself to the include path for sqlite3.h; on case-insensitive filesystems
# (macOS APFS) libc++'s `#include <version>` (C++20 feature-test header,
# transitively pulled in by <atomic>, <vector>, <string>, ...) resolves to
# sqlite/VERSION instead of the standard header and the compile aborts with
# "expected unqualified-id" on the version-string line. Strip it before
# snapshotting so the per-leg tarball never ships it. Sources don't need
# it at runtime — sqlite3.h carries SQLITE_VERSION as a #define.
log "stripping case-collision files that shadow C++ standard headers"
rm -f "${SRC_DIR}/external/sqlite/VERSION" "${SRC_DIR}/external/sqlite/version" 2>/dev/null || true

# cpython is NOT built by this workflow. It has its own dedicated
# pipeline — .github/workflows/5_builderpackage_embedded-python.yml, which
# runs framework/cpython/compile.sh in the manager builder image and
# publishes cpython_<arch>.tar.gz.
#
# This block only re-ships that already-built blob so the consolidated
# externals tarball is complete for downstream `make deps`. The source
# version comes from DEPS_VERSION (extracted from src/Makefile above), so
# the cpython we re-ship is the same one `make deps` would download. See
# the DEPS_VERSION note near the top of this script — running this workflow
# on a branch that has bumped DEPS_VERSION to a not-yet-published version
# will 404 here.
# Only manager legs trigger this; the agent EXTERNAL_RES has no $(CPYTHON).
if [ "${BUILD_TARGET}" = "manager" ]; then
    case "${ARCHITECTURE_TARGET}" in
        amd64) cpython_arch="x86_64" ;;
        arm64) cpython_arch="arm64" ;;
        *)     cpython_arch="" ;;
    esac
    if [ -n "${cpython_arch}" ]; then
        cpython_url="https://packages.wazuh.com/deps/${DEPS_VERSION}/libraries/sources/cpython_${cpython_arch}.tar.gz"
        cpython_out="${ARTIFACTS_DIR}/cpython_${cpython_arch}.passthrough.tar.gz"
        log "fetching cpython pass-through from ${cpython_url}"
        if curl -fsSL "${cpython_url}" -o "${cpython_out}"; then
            log "staged cpython pass-through: $(basename "${cpython_out}") ($(stat -c %s "${cpython_out}" 2>/dev/null || stat -f %z "${cpython_out}") bytes)"
        else
            err "cpython pass-through fetch failed from ${cpython_url}"
            rm -f "${cpython_out}"
        fi
    fi
fi

# Pre-build source snapshots. cpython ships only as the pass-through blob above:
# a repacked copy of its tree would add files to the set that nothing reads.
for name in ${DEPS_FOR_LEG}; do
    if ! on_leg "${name}" || [ "${name}" = "cpython" ]; then
        log "skipping ${name} on ${LEG_PLATFORM}"
        continue
    fi
    snapshot_source "${name}"
done

log "building externals via 'make build-external TARGET=${MAKE_TARGET}'"
# `build-external` (defined at src/Makefile:372) configures cmake then builds
# only build/external — exactly the subset we want, no Wazuh modules.
# Wipe any stale build/ dir first: a CMakeCache.txt left over from a local
# host build will pin paths to the host filesystem and break the in-container
# configure step ("source ... does not match the source ... used to generate
# cache").
rm -rf "${SRC_DIR}/build"
# audit-userspace's lib/Makefile.am overrides CC for its gen_tables helpers
# to $(CC_FOR_BUILD), which older autoconf (centos:6, wheezy) leaves empty
# in native builds — yielding "/bin/sh: DHAVE_CONFIG_H: command not found".
# Set CC_FOR_BUILD to the active compiler so the helper-build recipe runs.
export CC_FOR_BUILD="${CC:-gcc}"
export CXX_FOR_BUILD="${CXX:-g++}"
# Don't abort on build failure — snapshot_built below should still capture
# whatever deps did build successfully, which is useful for diagnostics. The
# script's exit code reflects the build-external outcome at the end.
set +e
make -j"${JOBS}" -C "${SRC_DIR}" TARGET="${MAKE_TARGET}" build-external
build_external_rc=$?
set -e
if [ "${build_external_rc}" -ne 0 ]; then
    err "make build-external returned ${build_external_rc}; continuing to snapshot whatever built"
fi

# Pattern B deps: src/external/CMakeLists.txt has two arms — an "imported"
# arm that consumes a precompiled .a in the source tree, and a fallback that
# does `add_library(ext_<name> STATIC ${EXTERNAL_DIR}/<dir>/<source>.c)`. The
# fallback emits libext_<name>.a into the cmake build tree, NOT into the
# source tree where the precompiled-detection arm looks on the next run /
# in a downstream consumer. snapshot_built() zips the source tree only, so
# without this step the produced tarball is source-only and the downstream
# Wazuh build re-compiles from source instead of consuming the precompiled
# archive we just produced. Copy each build-tree output to the path the
# detection arm reads from.
#
# Source for the (target, expected_path) pairs:
#   src/external/CMakeLists.txt lines 1199 / 1217 / 1239 (detection)
#                              lines 1206 / 1224 / 1247 (fallback)
PATTERN_B_PAIRS=(
    "ext_cjson:cJSON/libcjson.a"
    "ext_sqlite:sqlite/libsqlite3.a"
    "ext_procps:procps/libproc.a"
)
for pair in "${PATTERN_B_PAIRS[@]}"; do
    target="${pair%%:*}"
    dst_rel="${pair#*:}"
    build_lib="${SRC_DIR}/build/external/lib${target}.a"
    dst_path="${EXTERNAL_DIR}/${dst_rel}"
    if [ -f "${build_lib}" ]; then
        mkdir -p "$(dirname "${dst_path}")"
        cp -f "${build_lib}" "${dst_path}"
        log "restored pattern-B precompiled archive: ${dst_path} <- ${build_lib}"
    else
        log "pattern-B archive missing in build tree: ${build_lib} (build-external probably failed for this target)"
    fi
done

# Post-build snapshots.
for name in ${DEPS_FOR_LEG}; do
    if on_leg "${name}" && [ "${name}" != "cpython" ]; then
        snapshot_built "${name}"
    fi
done

log "done. artifacts in ${ARTIFACTS_DIR}:"
ls -la "${ARTIFACTS_DIR}"

# Surface the build-external outcome so the caller's exit status is meaningful.
exit "${build_external_rc:-0}"
