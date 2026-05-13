#!/bin/bash
#
# Wazuh external dependency builder (container-side).
#
# Runs inside one of the package builder Docker images (e.g.
# packages/debs/amd64/manager:<tag>). Driven by packages/generate_external.sh
# on the host.
#
# Inputs (env vars set by the host script):
#   BUILD_TARGET        agent | manager        (passed to `make TARGET=`)
#   ARCHITECTURE_TARGET amd64 | arm64 | ...    (used in artifact filenames)
#   SYSTEM              deb | rpm | macos | windows  (used in artifact filenames)
#   DEPS_TO_UPDATE      "name:version;name:version;..." (may be empty)
#   JOBS                parallel build jobs (defaults to nproc)
#   WAZUH_VERBOSE       "yes" enables `set -x`
#
# Sources (location varies by mode):
#   ${WAZUH_SRC}                  the working tree (default /wazuh-local-src
#                                 — the path the Linux/Windows builder
#                                 containers see; macOS native runs override
#                                 it to the actual checkout path).
#   ${WAZUH_SRC}/packages/external_sources.sh   the manifest
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

# shellcheck disable=SC1091
source "${WAZUH_SRC}/packages/external_sources.sh"

# Substitute {version}, {version_us}, and {version_concat} in a URL template.
# {version_concat} maps a dotted version like "3.51.1" to sqlite's
# concatenated form "3510100" — major (raw) + minor (2 digits) + patch (2
# digits) + a "00" trailing release counter. sqlite is the only consumer
# today; the format is documented at https://www.sqlite.org/download.html.
expand_url() {
    local template="$1" version="$2"
    local version_us="${version//./_}"
    local maj min pat
    IFS='.' read -r maj min pat _ <<< "${version}"
    local version_concat
    version_concat="$(printf '%d%02d%02d00' "${maj:-0}" "${min:-0}" "${pat:-0}")"
    template="${template//\{version\}/${version}}"
    template="${template//\{version_us\}/${version_us}}"
    template="${template//\{version_concat\}/${version_concat}}"
    echo "$template"
}

# Resolve a manifest URL template + version to a concrete download URL.
# Two URL kinds are supported:
#   - Plain URL with {version}/{version_us} placeholders (passthrough via
#     expand_url). Used for non-GitHub upstreams (curl.se, openssl.org, IANA,
#     freedesktop.org, etc.) and GitHub deps where the auto-archive URL or a
#     known release-asset URL is hard-coded.
#   - "gh:owner/repo:tag-template" — call the GitHub releases API for the tag
#     and pick the first `.tar.{gz,bz2,xz}` named release asset, falling back
#     to the auto-generated `tarball_url` (the same blob as
#     `/archive/refs/tags/<tag>.tar.gz`) if the tag has no assets. This
#     handles two pain points: (a) projects whose asset filenames don't
#     follow our guessable patterns (e.g. PCRE2 publishes `pcre2-10.42.tar.gz`
#     under tag `pcre2-10.42`, no patch suffix), (b) future bumps to versions
#     where upstream changes asset naming conventions.
#
# Uses GITHUB_TOKEN for auth when available (CI workflows already set it via
# secrets.GITHUB_TOKEN). Without auth, the API allows ~60 unauthenticated
# requests per hour per IP — enough for one full 28-dep run.
resolve_url() {
    local template="$1" version="$2" format="${3:-tar.gz}"
    if [[ "${template}" != gh:* ]]; then
        expand_url "${template}" "${version}"
        return 0
    fi

    # Format: gh:owner/repo:tag-template
    local rest="${template#gh:}"
    local owner_repo="${rest%%:*}"
    local tag_template="${rest#*:}"
    if [ -z "${owner_repo}" ] || [ -z "${tag_template}" ] || [ "${owner_repo}" = "${tag_template}" ]; then
        err "malformed gh: URL '${template}' (expected 'gh:owner/repo:tag-template')"
        return 1
    fi
    local tag="${tag_template//\{version\}/${version}}"
    local api_url="https://api.github.com/repos/${owner_repo}/releases/tags/${tag}"

    local auth_args=()
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        auth_args=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    fi

    local api_response
    if ! api_response="$(curl -fsSL "${auth_args[@]}" \
            -H "Accept: application/vnd.github+json" \
            --connect-timeout 15 --max-time 30 \
            "${api_url}")"; then
        err "GitHub API call failed: ${api_url}"
        return 1
    fi

    # Pick the first named asset whose extension matches the declared format
    # (avoids mismatches like resolving to .tar.bz2 when the manifest and
    # extract logic expect .tar.gz). Fall back to .tarball_url (always .tar.gz)
    # when no asset matches. We parse with grep instead of jq because the
    # legacy builder images don't ship jq and we don't want to add it just
    # for one curl response.
    local resolved
    resolved="$(printf '%s' "${api_response}" \
        | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' \
        | sed -E 's/.*"([^"]+)"$/\1/' \
        | grep -E "\.${format}\$" | head -n1)"
    if [ -z "${resolved}" ]; then
        resolved="$(printf '%s' "${api_response}" \
            | grep -oE '"tarball_url"[[:space:]]*:[[:space:]]*"[^"]+"' \
            | sed -E 's/.*"([^"]+)"$/\1/' | head -n1)"
    fi

    if [ -z "${resolved}" ]; then
        err "GitHub API returned no usable URL for ${owner_repo} tag ${tag}"
        return 1
    fi
    echo "${resolved}"
}

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

# Replace src/external/<target_dir>/ with the upstream tarball for <name>:<version>.
replace_dep_source() {
    local name="$1" version="$2"
    local url_template="${EXT_URL[$name]:-}"
    if [ -z "${url_template}" ] || [ "${url_template}" = "TBD" ]; then
        err "no manifest URL for '${name}' (entry missing or marked TBD); skipping replacement"
        return 1
    fi
    local format="${EXT_FORMAT[$name]}"
    local strip="${EXT_STRIP[$name]}"
    local target_dir="${EXT_TARGET[$name]}"
    local linux_only="${EXT_LINUX_ONLY[$name]}"

    if [ "${linux_only}" = "true" ] && [ "${SYSTEM}" != "deb" ] && [ "${SYSTEM}" != "rpm" ]; then
        log "skipping '${name}' update on ${SYSTEM} (linux-only dep)"
        return 0
    fi

    local url
    if ! url="$(resolve_url "${url_template}" "${version}" "${format}")"; then
        return 1
    fi
    local archive="${DOWNLOAD_DIR}/${name}.${format}"

    log "fetching ${name} ${version} from ${url}"
    if ! download "${url}" "${archive}"; then
        err "failed to download ${name} from ${url}"
        return 1
    fi

    log "replacing ${EXTERNAL_DIR}/${target_dir}/ with new source"
    rm -rf "${EXTERNAL_DIR:?}/${target_dir}"
    extract "${archive}" "${format}" "${EXTERNAL_DIR}/${target_dir}" "${strip}"
}

# Stage every dep listed in DEPS_TO_UPDATE.
# Per-dep download failures are logged and skipped so the run can produce a
# full validation report of the manifest's URL templates instead of aborting
# on the first bad URL. Skipped deps fall back to the version `make deps`
# already extracted from the Wazuh source mirror.
apply_updates() {
    if [ -z "${DEPS_TO_UPDATE:-}" ]; then
        log "no DEPS_TO_UPDATE provided; rebuilding everything from currently vendored sources"
        return 0
    fi

    local IFS=';'
    local skipped=""
    for entry in ${DEPS_TO_UPDATE}; do
        [ -z "${entry}" ] && continue
        local name="${entry%%:*}"
        local version="${entry#*:}"
        if [ -z "${name}" ] || [ -z "${version}" ] || [ "${name}" = "${entry}" ]; then
            err "invalid dep spec '${entry}' (expected 'name:version'); skipping"
            skipped="${skipped} ${entry}"
            continue
        fi
        if [ -z "${EXT_URL[$name]:-}" ]; then
            err "unknown dep '${name}' (not in external_sources.sh); skipping"
            skipped="${skipped} ${name}"
            continue
        fi
        if ! replace_dep_source "${name}" "${version}"; then
            skipped="${skipped} ${name}:${version}"
        fi
    done
    if [ -n "${skipped}" ]; then
        log "apply_updates: deps that did not get an upstream replacement:${skipped}"
    fi
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

# Read EXTERNAL_RES out of src/Makefile so we don't duplicate the dep list here.
# Returns (whitespace-separated) the deps that apply to this BUILD_TARGET.
#
# Substitutes the literal token `$(CPYTHON)` to `cpython` (defined at
# src/Makefile:404 as `CPYTHON := cpython`). awk doesn't expand make
# variables, so without this the manager dep list would carry an unresolved
# `$(CPYTHON)` token that no downstream step matches.
collect_deps_for_target() {
    local target="$1"
    awk -v target="${target}" '
        function expand(s) {
            gsub(/\$\(CPYTHON\)/, "cpython", s)
            return s
        }
        /^EXTERNAL_RES[[:space:]]*:=/ {
            sub(/.*:=[[:space:]]*/, "", $0)
            base = expand($0)
            getline_done = 0
        }
        target == "manager" && /EXTERNAL_RES[[:space:]]*\+=/ {
            sub(/.*\+=[[:space:]]*/, "", $0)
            extra = expand($0)
        }
        END {
            print base " " extra
        }
    ' "${SRC_DIR}/Makefile"
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

# Determine the dep set this leg cares about up-front.
DEPS_FOR_LEG="$(collect_deps_for_target "${BUILD_TARGET}")"
log "deps for this leg: ${DEPS_FOR_LEG}"

# Populate source directories via `make deps EXTERNAL_SRC_ONLY=yes`.
log "removing stale tar/tar.gz intermediates under src/external/"
find "${EXTERNAL_DIR}" -maxdepth 1 \( -name '*.tar' -o -name '*.tar.gz' \) -type f -delete 2>/dev/null || true

log "pre-cleaning src/external/<dep>/ dirs for clean tar extract"
for name in ${DEPS_FOR_LEG}; do
    rm -rf "${EXTERNAL_DIR:?}/${name}"
done

log "running 'make deps' (EXTERNAL_SRC_ONLY=yes) to populate dep sources"
make -C "${SRC_DIR}" EXTERNAL_SRC_ONLY=yes deps TARGET="${MAKE_TARGET}"

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

apply_updates

# cpython is a precompiled pass-through, not a from-source rebuild. The
# `make deps` step above already pulled the per-arch precompiled blob
# (cpython_x86_64.tar.gz or cpython_arm64.tar.gz) from
# packages.wazuh.com/deps/<ver>/libraries/sources/ and dropped it at
# src/external/cpython.tar.gz (file rename happens in the Makefile recipe;
# the tarball's internal layout is still `cpython_<arch>/`). Stage that
# file as a *.passthrough.tar.gz artifact so generate_external.sh ships it
# verbatim as libraries/sources/cpython_<arch>.tar.gz — matching the S3
# layout the downstream `make deps` consumes. Only manager legs ever
# trigger this; the agent EXTERNAL_RES has no $(CPYTHON) entry.
if [ "${BUILD_TARGET}" = "manager" ]; then
    case "${ARCHITECTURE_TARGET}" in
        amd64) cpython_arch="x86_64" ;;
        arm64) cpython_arch="arm64" ;;
        *)     cpython_arch="" ;;
    esac
    if [ -n "${cpython_arch}" ]; then
        if [ -f "${EXTERNAL_DIR}/cpython.tar.gz" ]; then
            cp "${EXTERNAL_DIR}/cpython.tar.gz" \
                "${ARTIFACTS_DIR}/cpython_${cpython_arch}.passthrough.tar.gz"
            log "staged cpython pass-through: cpython_${cpython_arch}.tar.gz"
        else
            err "cpython pass-through skipped: ${EXTERNAL_DIR}/cpython.tar.gz missing after make deps"
        fi
    fi
fi

# Pre-build source snapshots.
for name in ${DEPS_FOR_LEG}; do
    # Skip deps that the manifest filters out for non-Linux legs.
    if [ "${EXT_LINUX_ONLY[$name]:-false}" = "true" ] && \
       [ "${SYSTEM}" != "deb" ] && [ "${SYSTEM}" != "rpm" ]; then
        log "skipping ${name} on ${SYSTEM} (linux-only)"
        continue
    fi
    if [ -z "${EXT_URL[$name]:-}" ]; then
        log "skipping ${name} (not in manifest)"
        continue
    fi
    snapshot_source "${name}"
done

# Stage precompiled binaries for deps whose source-rebuild path is broken
# in the legacy builder images. src/external/CMakeLists.txt has if(EXISTS)
# short-circuits that pick precompiled .a files when present, skipping the
# from-source ExternalProject_Add. Wazuh's normal CI always has these
# precompiled tarballs (downloaded by `make deps` without EXTERNAL_SRC_ONLY)
# so the from-source path is rarely exercised and has known issues:
#   - libbpf-bootstrap: needs clang ≥7 with BPF backend and kernel UAPI
#     headers ≥4.13. Wazuh team builds it in dedicated centos:7 +
#     clang-15-from-source images (issue 28626) and uploads the result.
#   - libffi: ExternalProject_Add's BUILD_BYPRODUCTS doesn't translate to
#     a working make rule under the Make generator with BUILD_IN_SOURCE TRUE.
#     wazuhext's link step then fails with "No rule to make target".
# We reuse the existing precompiled tarballs from packages.wazuh.com.
# Done after the source-snapshot loop so the *_src.zip artifacts stay clean.
# Future bumps of these specific deps would need the original build env
# (per-image toolchain or external CI), so they're out of scope here.
stage_precompiled() {
    # $1 = dep name (folder under src/external/), $2 = sentinel file path
    # (relative to src/external/) whose presence triggers the if(EXISTS)
    # short-circuit in src/external/CMakeLists.txt.
    local name="$1"
    local sentinel="$2"
    local arch_path
    case "${ARCHITECTURE_TARGET}" in
        amd64)  arch_path="amd64" ;;
        arm64)  arch_path="aarch64" ;;
        *)      log "stage_precompiled: unsupported arch ${ARCHITECTURE_TARGET}; skipping ${name}"; return 0 ;;
    esac
    local url="https://packages.wazuh.com/deps/99-29585/libraries/linux/${arch_path}/${name}.tar.gz"
    local tar="${DOWNLOAD_DIR}/${name}-precompiled.tar.gz"
    log "staging precompiled ${name} from ${url}"
    if ! curl -fsSL "${url}" -o "${tar}"; then
        err "could not fetch precompiled ${name}; build-external will attempt to rebuild from source"
        return 0
    fi
    tar -xzf "${tar}" -C "${SRC_DIR}/external/"
    if [ -f "${SRC_DIR}/external/${sentinel}" ]; then
        log "${name} binary staged; build-external will skip recompilation"
    else
        err "${name} tarball extracted but sentinel ${sentinel} not present; CMakeLists short-circuit will not fire"
    fi
}

if { [ "${SYSTEM}" = "deb" ] || [ "${SYSTEM}" = "rpm" ]; }; then
    # libbpf-bootstrap: IS_LINUX AND IS_AGENT — agent target only.
    if [ "${BUILD_TARGET}" = "agent" ]; then
        stage_precompiled libbpf-bootstrap libbpf-bootstrap/build/modern.bpf.o
    fi
    # libffi: NOT IS_AGENT — manager target only.
    if [ "${BUILD_TARGET}" = "manager" ]; then
        stage_precompiled libffi libffi/server/.libs/libffi.a
    fi
fi

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
    if [ "${EXT_LINUX_ONLY[$name]:-false}" = "true" ] && \
       [ "${SYSTEM}" != "deb" ] && [ "${SYSTEM}" != "rpm" ]; then
        continue
    fi
    if [ -z "${EXT_URL[$name]:-}" ]; then
        continue
    fi
    snapshot_built "${name}"
done

log "done. artifacts in ${ARTIFACTS_DIR}:"
ls -la "${ARTIFACTS_DIR}"

# Surface the build-external outcome so the caller's exit status is meaningful.
exit "${build_external_rc:-0}"
