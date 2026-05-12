#!/bin/bash
#
# Wazuh external dependency builder (host-side).
#
# Drives the per-leg external dependency rebuild. Picks the right Docker image
# for the (system, architecture) combo, mounts the working tree, runs
# packages/build_external.sh inside the container, and exposes the per-dep
# zip artifacts on the host.
#
# Currently supports the 4 Linux Docker legs (deb/rpm x amd64/arm64).
# macOS (native) and Windows (MinGW cross-compile) legs are added in
# follow-up commits.

set -e

CURRENT_PATH="$(cd "$(dirname "$0")"; pwd -P)"
WAZUH_PATH="$(cd "${CURRENT_PATH}/.."; pwd -P)"

ARCHITECTURE=""
SYSTEM=""
TARGET="manager"
DOCKER_TAG="latest"
DEPS_TO_UPDATE=""
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
VERBOSE=""
OUTDIR="${CURRENT_PATH}/output_externals"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

  -s, --system <deb|rpm>           [Required] Builder image family.
  -a, --architecture <amd64|arm64> [Required] Target architecture.
  -t, --target <agent|manager>     [Optional] Build set. Default: manager.
      --tag <tag>                  [Optional] Docker image tag. Default: latest.
      --dependencies "<spec>"      [Optional] "name:version;name:version;..."
                                   Empty = rebuild all from currently vendored
                                   sources; nothing is replaced.
      --jobs <n>                   [Optional] Parallel make jobs.
      --output <path>              [Optional] Host output dir (collected zips).
                                   Default: \$CURRENT_PATH/output_externals.
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
        --dependencies)      DEPS_TO_UPDATE="$2"; shift 2 ;;
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
echo "[generate_external] deps='${DEPS_TO_UPDATE}'"
echo "[generate_external] output=${OUTDIR}"

# Linux deb/rpm uses the existing builder Docker images. macOS runs natively
# on the macOS runner; Windows runs natively on a Linux runner with MinGW
# installed (the cross-compile target is i686-w64-mingw32, build artifacts
# are .a/.lib files for Windows). Neither macOS nor Windows uses a Wazuh
# package builder image.
if [ "${SYSTEM}" = "macos" ] || [ "${SYSTEM}" = "windows" ]; then
    echo "[generate_external] mode=native (no docker)"
    env \
        WAZUH_SRC="${WAZUH_PATH}" \
        ARTIFACTS_DIR="${OUTDIR}/external_artifacts" \
        SYSTEM="${SYSTEM}" \
        BUILD_TARGET="${TARGET}" \
        ARCHITECTURE_TARGET="${ARCHITECTURE}" \
        DEPS_TO_UPDATE="${DEPS_TO_UPDATE}" \
        JOBS="${JOBS}" \
        WAZUH_VERBOSE="${VERBOSE}" \
        bash "${WAZUH_PATH}/packages/build_external.sh"
else
    CONTAINER_NAME="pkg_${SYSTEM}_${TARGET}_builder_${ARCHITECTURE}"
    echo "[generate_external] image=${CONTAINER_NAME}:${DOCKER_TAG}"

    # Run build_external.sh inside the existing builder image.
    # - /wazuh-local-src    working tree (read-write so we can replace src/external/)
    # - /var/local/wazuh    artifact output (build_external.sh writes
    #                       external_artifacts/ subdir here, we pull from there)
    # We override the image entrypoint because the default entrypoint
    # (docker_builder.sh) drives a full package build.
    docker run --rm -t \
        -v "${WAZUH_PATH}:/wazuh-local-src:Z" \
        -v "${OUTDIR}:/var/local/wazuh:Z" \
        -e SYSTEM="${SYSTEM}" \
        -e BUILD_TARGET="${TARGET}" \
        -e ARCHITECTURE_TARGET="${ARCHITECTURE}" \
        -e DEPS_TO_UPDATE="${DEPS_TO_UPDATE}" \
        -e JOBS="${JOBS}" \
        -e WAZUH_VERBOSE="${VERBOSE}" \
        --entrypoint /bin/bash \
        "${CONTAINER_NAME}:${DOCKER_TAG}" \
        /wazuh-local-src/packages/build_external.sh
fi

echo "[generate_external] per-dep zips:"
ls -la "${OUTDIR}/external_artifacts/" 2>/dev/null || echo "  (none — build may have failed)"

# Re-pack the per-dep zips into the S3 layout `make deps` consumes from
# packages.wazuh.com/deps/<version>/libraries/. Each runner emits a single
# tarball that already contains its slice of the libraries/ tree, so
# downloading every artifact from a run and extracting each into the same
# destination yields the complete tree — no aggregation job needed.
#
# Layout written by this leg:
#   libraries/<os>/<arch>/<dep>.tar.gz    binaries for this (system, arch)
#   libraries/sources/<dep>.tar.gz        upstream sources (every leg writes
#                                         identical content, so the final
#                                         tree has one copy regardless of
#                                         extract order)
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
    echo "[generate_external] no S3 path mapping for ${SYSTEM}-${ARCHITECTURE}; skipping pack step"
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

LIBS_DIR="${OUTDIR}/libraries"
PLATFORM_DIR="${LIBS_DIR}/${S3_PATH}"
SOURCES_DIR="${LIBS_DIR}/sources"
rm -rf "${LIBS_DIR}"
mkdir -p "${PLATFORM_DIR}" "${SOURCES_DIR}"

echo "[generate_external] packing zips into libraries/${S3_PATH}/ and libraries/sources/"

repack() {
    local zip="$1" dep="$2" dest="$3"
    local tmp
    tmp="$(mktemp -d)"
    unzip -q "${zip}" -d "${tmp}"
    if [ ! -d "${tmp}/${dep}" ]; then
        echo "[generate_external] WARN: ${zip} missing '${dep}/' dir — skipping" >&2
        rm -rf "${tmp}"
        return 0
    fi
    ( cd "${tmp}" && "${TAR}" -czf "${dest}/${dep}.tar.gz" --owner=0 --group=0 --no-same-owner "${dep}" )
    rm -rf "${tmp}"
}

bin_suffix="_${SYSTEM}_${ARCHITECTURE}.zip"
for zip in "${OUTDIR}/external_artifacts/"*.zip; do
    [ -f "${zip}" ] || continue
    base="$(basename "${zip}")"
    case "${base}" in
        *_src.zip)
            dep="${base%_src.zip}"
            repack "${zip}" "${dep}" "${SOURCES_DIR}"
            ;;
        *"${bin_suffix}")
            dep="${base%${bin_suffix}}"
            repack "${zip}" "${dep}" "${PLATFORM_DIR}"
            ;;
    esac
done

OUT_TARBALL="${OUTDIR}/externals-${SYSTEM}-${ARCHITECTURE}-${TARGET}.tar.gz"
( cd "${OUTDIR}" && "${TAR}" -czf "${OUT_TARBALL}" --owner=0 --group=0 --no-same-owner libraries )
echo "[generate_external] packed: ${OUT_TARBALL}"
ls -lh "${OUT_TARBALL}"
