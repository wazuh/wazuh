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
JOBS="$(nproc 2>/dev/null || echo 2)"
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
    deb|rpm) ;;
    *) echo "ERROR: unsupported --system '${SYSTEM}' (valid: deb, rpm)" >&2; exit 1 ;;
esac

case "${ARCHITECTURE}" in
    amd64|arm64) ;;
    *) echo "ERROR: only 'amd64' and 'arm64' are supported" >&2; exit 1 ;;
esac

case "${TARGET}" in
    agent|manager) ;;
    *) echo "ERROR: target must be 'agent' or 'manager'" >&2; exit 1 ;;
esac

if [ -n "${VERBOSE}" ]; then
    set -x
fi

CONTAINER_NAME="pkg_${SYSTEM}_${TARGET}_builder_${ARCHITECTURE}"
mkdir -p "${OUTDIR}"

echo "[generate_external] image=${CONTAINER_NAME}:${DOCKER_TAG}"
echo "[generate_external] target=${TARGET} system=${SYSTEM} arch=${ARCHITECTURE}"
echo "[generate_external] deps='${DEPS_TO_UPDATE}'"
echo "[generate_external] output=${OUTDIR}"

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

echo "[generate_external] artifacts:"
ls -la "${OUTDIR}/external_artifacts/" 2>/dev/null || echo "  (none — build may have failed)"
