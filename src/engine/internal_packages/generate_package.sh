#!/usr/bin/env bash
set -euo pipefail

# --- Defaults ----------------------------------------------
SYSTEM="deb"               # deb|rpm
ARCH_INPUT="amd64"         # amd64|x86_64|arm64|aarch64
REVISION="0"
JOBS="$(command -v nproc >/dev/null 2>&1 && nproc || echo 2)"
OUTDIR="$(pwd)/output"
DOCKER_TAG="local"
BRANCH=""                  # if empty, use locally mounted sources
CHECKSUM="no"              # yes|no
VERBOSE=""                 # if set, enable -x and export WAZUH_VERBOSE
CUSTOM_CODE_VOL=""

# --- Helpers -----------------------------------------------------------------
usage() {
  cat <<EOF
Usage: $0 [options]
  -a, --architecture <arch>    amd64|x86_64|arm64|aarch64
  --system <deb|rpm>           package system (recommended: deb)
  -r, --revision <rev>         package revision (default: 0)
  -j, --jobs <N>               parallelism for build.sh (default: nproc)
  -s, --store <dir>            output directory (default: ./output)
  -b, --branch <branch|tag>    build from GitHub branch/tag instead of local sources
  --checksum                   generate .sha512
  --tag <tag>                  docker image tag (default: local)
  --sources <abs_path>         mount local code at /wazuh-local-src inside the container
  --verbose                    verbose mode
  -h, --help                   this help
EOF
  exit "${1:-0}"
}

# Normalize architecture for path usage (amd64|arm64 only for internal paths)
norm_arch_path() {
  case "$1" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)             echo "amd64" ;;
  esac
}

# --- Argument parsing ---------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    -a|--architecture)     ARCH_INPUT="$2"; shift 2;;
    --system)              SYSTEM="$2"; shift 2;;
    -r|--revision)         REVISION="$2"; shift 2;;
    -j|--jobs)             JOBS="$2"; shift 2;;
    -s|--store)            OUTDIR="${2%/}"; shift 2;;
    -b|--branch)           BRANCH="$2"; shift 2;;
    --checksum)            CHECKSUM="yes"; shift 1;;
    --tag)                 DOCKER_TAG="$2"; shift 2;;
    --sources)             CUSTOM_CODE_VOL="-v $2:/wazuh-local-src"; shift 2;;
    --verbose)             VERBOSE="yes"; shift 1;;
    -h|--help)             usage 0;;
    *) echo "Unknown option: $1"; usage 1;;
  esac
done

[ -n "$VERBOSE" ] && set -x

SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd -P )"
# Prefer repo root (git), otherwise two levels up from packages/
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || echo "$(cd "$SCRIPT_DIR/.." && pwd -P)")"

ARCH_PATH="$(norm_arch_path "$ARCH_INPUT")"

# Expected layout: packages/<system>s/<...>/Dockerfile
DOCKERFILE_PATH="${SCRIPT_DIR}/${SYSTEM}s"
CONTAINER_NAME="pkg_${SYSTEM}_internal-tools_builder_${ARCH_PATH}"

mkdir -p "$OUTDIR"

# Ensure build helper scripts exist in Docker build context (your Dockerfile ADDs these)
for f in build.sh helper_function.sh gen_permissions.sh; do
  if [ -f "${SCRIPT_DIR}/${f}" ]; then
    cp -f "${SCRIPT_DIR}/${f}" "${DOCKERFILE_PATH}/" || true
  elif [ -f "${REPO_ROOT}/packages/${f}" ]; then
    cp -f "${REPO_ROOT}/packages/${f}" "${DOCKERFILE_PATH}/" || true
  fi
done

# Build the image for the selected system context
docker build -t "${CONTAINER_NAME}:${DOCKER_TAG}" "${DOCKERFILE_PATH}"

# If neither --branch nor --sources were provided, mount repo sources by default
if [ -z "$CUSTOM_CODE_VOL" ]; then
  ENGINE_DIR="${REPO_ROOT}/src/engine"
  if [ -d "$ENGINE_DIR" ]; then
    CUSTOM_CODE_VOL="-v ${ENGINE_DIR}:/wazuh-local-src"
  else
    echo "ERROR: '${ENGINE_DIR}' not found."
    exit 1
  fi
fi

# Environment consumed by build.sh inside the container
ENV_VARS=(
  -e SYSTEM="$SYSTEM"
  -e ARCHITECTURE_TARGET="$ARCH_PATH"
  -e WAZUH_BRANCH="$BRANCH"
)
[ -n "$VERBOSE" ] && ENV_VARS+=( -e WAZUH_VERBOSE=1 )

echo "[i] Running build in container: ${CONTAINER_NAME}:${DOCKER_TAG}"
echo "[i] System: $SYSTEM | Arch: $ARCH_PATH | Out: $OUTDIR"

docker run --rm -t \
  -v "${OUTDIR}:/var/local/wazuh" \
  ${CUSTOM_CODE_VOL} \
  "${ENV_VARS[@]}" \
  "${CONTAINER_NAME}:${DOCKER_TAG}" \
  "$REVISION" "$JOBS" "$CHECKSUM"
