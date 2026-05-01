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
# Sources (mounted by the host):
#   /wazuh-local-src              the working tree
#   /wazuh-local-src/packages/external_sources.sh   the manifest
#
# Output:
#   /var/local/wazuh/external_artifacts/<dep>_src.zip
#   /var/local/wazuh/external_artifacts/<dep>_<system>_<architecture>.zip

set -e

WAZUH_SRC="/wazuh-local-src"
SRC_DIR="${WAZUH_SRC}/src"
EXTERNAL_DIR="${SRC_DIR}/external"
ARTIFACTS_DIR="/var/local/wazuh/external_artifacts"
DOWNLOAD_DIR="/tmp/external_upstream"

JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

if [ "${WAZUH_VERBOSE}" = "yes" ]; then
    set -x
fi

mkdir -p "${ARTIFACTS_DIR}" "${DOWNLOAD_DIR}"

log() { echo "[external] $*"; }
err() { echo "[external][ERROR] $*" >&2; }

# Runtime tooling not always in the package builder images by default:
#   - zip/unzip: needed to write the per-dep snapshot archives and to extract
#     `.zip` upstream tarballs (e.g. fmt).
#   - clang: libbpf-bootstrap's CMake config calls FindBpfObject.cmake which
#     errors out without a clang executable.
# All idempotent; quiet on success.
_missing=""
for tool in zip unzip clang; do
    command -v "$tool" >/dev/null 2>&1 || _missing="${_missing} ${tool}"
done
if [ -n "${_missing}" ]; then
    log "installing missing tooling:${_missing}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y ${_missing} >/dev/null 2>&1 || apt-get install -y ${_missing} || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y ${_missing} >/dev/null 2>&1 || yum install -y ${_missing} || true
    fi
fi

# shellcheck disable=SC1091
source "${WAZUH_SRC}/packages/external_sources.sh"

# Substitute {version} and {version_us} in a URL template.
expand_url() {
    local template="$1" version="$2"
    local version_us="${version//./_}"
    template="${template//\{version\}/${version}}"
    template="${template//\{version_us\}/${version_us}}"
    echo "$template"
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
    url="$(expand_url "${url_template}" "${version}")"
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
collect_deps_for_target() {
    local target="$1"
    awk -v target="${target}" '
        /^EXTERNAL_RES[[:space:]]*:=/ {
            sub(/.*:=[[:space:]]*/, "", $0)
            base = $0
            getline_done = 0
        }
        target == "manager" && /EXTERNAL_RES[[:space:]]*\+=/ {
            sub(/.*\+=[[:space:]]*/, "", $0)
            extra = $0
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

# Clean stale tarball intermediates from prior interrupted runs. The Makefile's
# `make deps` recipe pipes through `gunzip` (no -f) and prompts interactively
# if `external/<dep>.tar` already exists, which deadlocks the build.
log "removing stale tar/tar.gz intermediates under src/external/"
find "${EXTERNAL_DIR}" -maxdepth 1 \( -name '*.tar' -o -name '*.tar.gz' \) -type f -delete 2>/dev/null || true

# Determine the dep set this leg cares about up-front so we can pre-clean.
DEPS_FOR_LEG="$(collect_deps_for_target "${BUILD_TARGET}")"
log "deps for this leg: ${DEPS_FOR_LEG}"

# Pre-clean every dep dir before `make deps` extracts into them. Some of the
# Wazuh-mirror tarballs include symlinks (e.g. flatbuffers' java test fixtures)
# whose targets are stored as separate entries; tar can't replace an existing
# directory with a symlink, so a stale tree from a prior run causes
# "Cannot open: File exists" failures. Wiping the dirs makes `make deps`
# extract into clean state. Caller can `git checkout src/external/` afterwards.
log "pre-cleaning src/external/<dep>/ dirs for clean tar extract"
for name in ${DEPS_FOR_LEG}; do
    rm -rf "${EXTERNAL_DIR:?}/${name}"
done

# Order matters: `make deps` extracts the Wazuh-mirror source tarballs over
# src/external/<name>/, so it must run BEFORE we replace specific deps with
# upstream sources. Otherwise our replacements get overwritten.
log "running 'make deps' (EXTERNAL_SRC_ONLY=yes) to populate dep sources"
make -C "${SRC_DIR}" EXTERNAL_SRC_ONLY=yes deps TARGET="${BUILD_TARGET}"

apply_updates

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

log "building externals via 'make build-external TARGET=${BUILD_TARGET}'"
# `build-external` (defined at src/Makefile:372) configures cmake then builds
# only build/external — exactly the subset we want, no Wazuh modules.
# Wipe any stale build/ dir first: a CMakeCache.txt left over from a local
# host build will pin paths to the host filesystem and break the in-container
# configure step ("source ... does not match the source ... used to generate
# cache").
rm -rf "${SRC_DIR}/build"
# Don't abort on build failure — snapshot_built below should still capture
# whatever deps did build successfully, which is useful for diagnostics. The
# script's exit code reflects the build-external outcome at the end.
set +e
make -j"${JOBS}" -C "${SRC_DIR}" TARGET="${BUILD_TARGET}" build-external
build_external_rc=$?
set -e
if [ "${build_external_rc}" -ne 0 ]; then
    err "make build-external returned ${build_external_rc}; continuing to snapshot whatever built"
fi

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
