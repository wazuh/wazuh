#!/bin/bash
#
# Wazuh external dependency builder (host-side).
#
# Drives the per-leg external dependency rebuild. Picks the right Docker image
# for the (system, architecture) combo, mounts the working tree, runs
# packages/externals/build_external.sh inside the container, and exposes the
# per-dep zip artifacts on the host.
#
# Linux deb/rpm legs run inside the pkg_<sys>_<target>_builder_<arch> image.
# The Windows MinGW cross-compile leg runs inside compile_windows_agent
# (ubuntu:22.04 with the mingw toolchain pre-baked — same image the official
# Windows agent build uses). macOS legs run natively on the macOS runner.

set -e

CURRENT_PATH="$(cd "$(dirname "$0")"; pwd -P)"
# This script lives in packages/externals/, so the repo root is two levels up.
WAZUH_PATH="$(cd "${CURRENT_PATH}/../.."; pwd -P)"

ARCHITECTURE=""
SYSTEM=""
TARGET="manager"
DOCKER_TAG="latest"
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
VERBOSE=""
OUTDIR="${WAZUH_PATH}/packages/output_externals"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

  -s, --system <deb|rpm>           [Required] Builder image family.
  -a, --architecture <amd64|arm64> [Required] Target architecture.
  -t, --target <agent|manager>     [Optional] Build set. Default: manager.
      --tag <tag>                  [Optional] Docker image tag. Default: latest.
      --jobs <n>                   [Optional] Parallel make jobs.
      --output <path>              [Optional] Host output dir (collected zips).
                                   Default: <repo>/packages/output_externals.
      --verbose                    [Optional] Print commands as they run.
  -h, --help                       Show this help.
EOF
    exit "$1"
}

while [ -n "$1" ]; do
    case "$1" in
        -s|--system)         SYSTEM="$2"; shift 2 ;;
        -a|--architecture)   ARCHITECTURE="$2"; shift 2 ;;
        -t|--target)         TARGET="$2"; shift 2 ;;
        --tag)               DOCKER_TAG="$2"; shift 2 ;;
        --jobs)              JOBS="$2"; shift 2 ;;
        --output)            OUTDIR="$2"; shift 2 ;;
        --verbose)           VERBOSE="yes"; shift 1 ;;
        -h|--help)           usage 0 ;;
        *)                   echo "unknown arg: $1" >&2; usage 1 ;;
    esac
done

if [ -z "${SYSTEM}" ] || [ -z "${ARCHITECTURE}" ]; then
    echo "ERROR: --system and --architecture are required" >&2
    usage 1
fi

case "${SYSTEM}" in
    deb|rpm|macos|windows) ;;
    *) echo "ERROR: unsupported --system '${SYSTEM}' (valid: deb, rpm, macos, windows)" >&2; exit 1 ;;
esac

case "${ARCHITECTURE}" in
    amd64|arm64|intel64|i686) ;;
    *) echo "ERROR: unsupported --architecture '${ARCHITECTURE}' (valid: amd64, arm64, intel64, i686)" >&2; exit 1 ;;
esac

# Per-system architecture validation. Each system has a fixed set of valid
# arches, and arches are not portable across systems.
case "${SYSTEM}-${ARCHITECTURE}" in
    deb-amd64|deb-arm64|rpm-amd64|rpm-arm64) ;;
    macos-intel64|macos-arm64) ;;
    windows-i686) ;;  # Wazuh's Windows agent is always 32-bit MinGW cross-compile
    *)
        echo "ERROR: invalid combination ${SYSTEM}-${ARCHITECTURE}." >&2
        echo "       Valid: deb-{amd64,arm64}, rpm-{amd64,arm64}, macos-{intel64,arm64}, windows-i686" >&2
        exit 1
        ;;
esac

case "${TARGET}" in
    agent|manager) ;;
    *) echo "ERROR: target must be 'agent' or 'manager'" >&2; exit 1 ;;
esac

# macOS and Windows are agent-only (manager doesn't run on either).
if { [ "${SYSTEM}" = "macos" ] || [ "${SYSTEM}" = "windows" ]; } && [ "${TARGET}" = "manager" ]; then
    echo "ERROR: ${SYSTEM} legs are agent-only (manager doesn't run there)" >&2
    exit 1
fi

if [ -n "${VERBOSE}" ]; then
    set -x
fi

mkdir -p "${OUTDIR}"

echo "[generate_external] target=${TARGET} system=${SYSTEM} arch=${ARCHITECTURE}"
echo "[generate_external] output=${OUTDIR}"

# Sources come from packages/externals/dependencies.json, each from its own URL.
# Not every builder image has python3, so the host flattens it to bash arrays
# the leg sources.
DEPS_ENV_FILE="external_sources.env"
python3 "${CURRENT_PATH}/deps.py" flatten > "${OUTDIR}/${DEPS_ENV_FILE}"

# macOS runs natively on the macOS runner (no Docker available, host toolchain
# is what we ship against). Every other leg runs inside a pinned Wazuh builder
# image so the host glibc the build was produced against is the image's, not
# the runner's:
#   - deb/rpm   -> pkg_<sys>_<target>_builder_<arch>      (centos:6/7 era)
#   - windows   -> compile_windows_agent                   (ubuntu:22.04, the
#                                                          same image used by
#                                                          5_builderpackage_agent-windows.yml's
#                                                          downstream consumers)
# Without the compile_windows_agent pin, the windows leg picked up whatever
# glibc the wz-linux-amd64 runner happened to ship; downstream agent builds
# that re-consumed the packed windows externals on the 22.04 image then
# missed the newer symbols.
if [ "${SYSTEM}" = "macos" ]; then
    echo "[generate_external] mode=native (no docker)"
    env \
        WAZUH_SRC="${WAZUH_PATH}" \
        ARTIFACTS_DIR="${OUTDIR}/external_artifacts" \
        SYSTEM="${SYSTEM}" \
        BUILD_TARGET="${TARGET}" \
        ARCHITECTURE_TARGET="${ARCHITECTURE}" \
        DEPS_ENV="${OUTDIR}/${DEPS_ENV_FILE}" \
        DEPS_BUILD="${DEPS_BUILD:-}" \
        DEPS_POOL_URL="${DEPS_POOL_URL:-}" \
        JOBS="${JOBS}" \
        WAZUH_VERBOSE="${VERBOSE}" \
        bash "${WAZUH_PATH}/packages/externals/build_external.sh"
else
    if [ "${SYSTEM}" = "windows" ]; then
        CONTAINER_NAME="compile_windows_agent"
    else
        CONTAINER_NAME="pkg_${SYSTEM}_${TARGET}_builder_${ARCHITECTURE}"
    fi
    echo "[generate_external] image=${CONTAINER_NAME}:${DOCKER_TAG}"

    # Run build_external.sh inside the builder image.
    # - /wazuh-local-src    working tree (read-write so we can replace src/external/)
    # - /var/local/wazuh    artifact output (build_external.sh writes
    #                       external_artifacts/ subdir here, we pull from there)
    # We override the image entrypoint because each image's default entrypoint
    # drives a full package build (docker_builder.sh on the rpm/deb images,
    # entrypoint.sh on compile_windows_agent).
    docker run --rm -t \
        -v "${WAZUH_PATH}:/wazuh-local-src:Z" \
        -v "${OUTDIR}:/var/local/wazuh:Z" \
        -e SYSTEM="${SYSTEM}" \
        -e BUILD_TARGET="${TARGET}" \
        -e ARCHITECTURE_TARGET="${ARCHITECTURE}" \
        -e DEPS_ENV="/var/local/wazuh/${DEPS_ENV_FILE}" \
        -e DEPS_BUILD="${DEPS_BUILD:-}" \
        -e DEPS_POOL_URL="${DEPS_POOL_URL:-}" \
        -e JOBS="${JOBS}" \
        -e WAZUH_VERBOSE="${VERBOSE}" \
        --entrypoint /bin/bash \
        "${CONTAINER_NAME}:${DOCKER_TAG}" \
        /wazuh-local-src/packages/externals/build_external.sh
fi

echo "[generate_external] per-dep zips:"
ls -la "${OUTDIR}/external_artifacts/" 2>/dev/null || echo "  (none — build may have failed)"

# Re-pack the per-dep zips into the pool layout `make deps` consumes from
# packages.wazuh.com/deps/pool/, under the refs of src/deps.lock.mk:
#   pool/<ref>/sources/<dep>.tar.gz    the source tree (identical on every leg)
#   pool/<ref>/<os>/<arch>/<dep>.tar.gz  what this leg compiled, when it compiled
#                                       something: a leg that only has the
#                                       sources of a dependency (procps on the
#                                       manager legs) leaves its platform to others
# The consolidate job merges the legs; where two legs compiled the same
# dependency it keeps the agent leg's copy (see consolidate.sh).
#
# Inner and outer tarballs use owner=0/group=0 so they extract under any UID.
case "${SYSTEM}-${ARCHITECTURE}" in
    deb-amd64|rpm-amd64) S3_PATH="linux/amd64" ;;
    deb-arm64|rpm-arm64) S3_PATH="linux/aarch64" ;;
    macos-intel64)       S3_PATH="darwin/amd64" ;;
    macos-arm64)         S3_PATH="darwin/aarch64" ;;
    windows-i686)        S3_PATH="windows" ;;
    *)                   S3_PATH="" ;;
esac

if [ -z "${S3_PATH}" ]; then
    echo "[generate_external] no pool path mapping for ${SYSTEM}-${ARCHITECTURE}; skipping pack step"
    exit 0
fi

# macOS's /usr/bin/tar is BSD tar and rejects --owner/--group/--no-same-owner.
# Workflow installs gnu-tar (gtar) via brew on macOS legs; everywhere else
# `tar` already is GNU tar.
if command -v gtar >/dev/null 2>&1; then
    TAR="gtar"
else
    TAR="tar"
fi

if [ ! -d "${OUTDIR}/external_artifacts" ]; then
    echo "[generate_external] no external_artifacts/ dir; nothing to pack"
    exit 0
fi

POOL_DIR="${OUTDIR}/pool"
LOCK="${WAZUH_PATH}/src/deps.lock.mk"
rm -rf "${POOL_DIR}"
# A leg that builds nothing still ships an (empty) pool/.
mkdir -p "${POOL_DIR}"

# Pack <zip>'s <dep>/ into <dest>/<dep>.tar.gz; with `compiled`, only if it holds a library.
repack() {
    local zip="$1" dep="$2" dest="$3" only_compiled="${4:-}"
    local tmp
    tmp="$(mktemp -d)"
    unzip -q "${zip}" -d "${tmp}"
    if [ ! -d "${tmp}/${dep}" ]; then
        echo "[generate_external] WARN: ${zip} missing '${dep}/' dir — skipping" >&2
    elif [ -n "${only_compiled}" ] && [ -z "$(find "${tmp}/${dep}" -type f \( -name '*.a' -o -name '*.so' -o -name '*.so.*' -o -name '*.lib' -o -name '*.dylib' \) | head -n1)" ]; then
        echo "[generate_external] ${dep}: nothing compiled on this leg; no ${S3_PATH} tarball"
    else
        mkdir -p "${dest}"
        ( cd "${tmp}" && "${TAR}" -czf "${dest}/${dep}.tar.gz" --owner=0 --group=0 --no-same-owner "${dep}" )
    fi
    rm -rf "${tmp}"
}

bin_suffix="_${SYSTEM}_${ARCHITECTURE}.zip"
for zip in "${OUTDIR}/external_artifacts/"*.zip; do
    [ -f "${zip}" ] || continue
    base="$(basename "${zip}")"
    case "${base}" in
        *_src.zip)          dep="${base%_src.zip}" ;;
        *"${bin_suffix}")   dep="${base%${bin_suffix}}" ;;
        *)                  continue ;;
    esac
    ref="$(sed -n "s/^DEP_REF_${dep} := //p" "${LOCK}")"
    if [ -z "${ref}" ]; then
        echo "[generate_external] ERROR: no DEP_REF_${dep} in ${LOCK}" >&2
        exit 1
    fi
    case "${base}" in
        *_src.zip) repack "${zip}" "${dep}" "${POOL_DIR}/${ref}/sources" ;;
        *)         repack "${zip}" "${dep}" "${POOL_DIR}/${ref}/${S3_PATH}" compiled ;;
    esac
done

# What the leg installed on the fly, for the manifests (consolidate.sh).
rm -rf "${OUTDIR}/toolchain"
mkdir -p "${OUTDIR}/toolchain"
if [ -f "${OUTDIR}/external_artifacts/toolchain.txt" ]; then
    cp "${OUTDIR}/external_artifacts/toolchain.txt" "${OUTDIR}/toolchain/${SYSTEM}-${ARCHITECTURE}-${TARGET}.txt"
fi

OUT_TARBALL="${OUTDIR}/externals-${SYSTEM}-${ARCHITECTURE}-${TARGET}.tar.gz"
( cd "${OUTDIR}" && "${TAR}" -czf "${OUT_TARBALL}" --owner=0 --group=0 --no-same-owner pool toolchain )
echo "[generate_external] packed: ${OUT_TARBALL}"
ls -lh "${OUT_TARBALL}"
