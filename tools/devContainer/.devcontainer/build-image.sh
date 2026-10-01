#!/usr/bin/env bash
# Build the devContainer image from its recipe (image.devcontainer.json: Dockerfile + features).
# Single entry point for both flows: a local build that leaves <repo>:<tag> in the local Docker,
# and the CI build that pushes one platform by digest.
set -euo pipefail

CLI_VERSION="0.89.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(dirname "$SCRIPT_DIR")"
RUNTIME_CONFIG="$SCRIPT_DIR/devcontainer.json"
RECIPE_CONFIG="$SCRIPT_DIR/image.devcontainer.json"

PLATFORM=""
IMAGE_REPO=""
IMAGE_TAG=""
DIGEST_FILE=""
BUILD_LOG=""

usage() {
  cat <<EOF
Usage:
  $0 [--platform linux/amd64|linux/arm64] [--image <repo>] [--tag <tag>] [--push-by-digest <file>]

Builds the devContainer image from ${RECIPE_CONFIG##*/} with the devcontainer CLI
(the one in PATH, or npx --yes @devcontainers/cli@${CLI_VERSION}).

Examples:
  $0
      Local build for this host's platform; the image stays in the local Docker as the
      repository:tag of the "image" line of devcontainer.json. Reopen the devContainer to use it.
  WAZUH_DEVCONTAINER_IMAGE=ghcr.io/<fork>/wazuh-devcontainer $0 --tag 5.0
      Same, under another repository.
  BUILDX_BUILDER=<docker-container builder> $0 --platform linux/arm64 --push-by-digest digest.txt
      CI flow: push the image by digest to <repo> and write the digest to digest.txt.

Options:
  --platform P           linux/amd64 or linux/arm64. Default: the host's (uname -m)
  --image REPO           Image repository, without tag. Default: \$WAZUH_DEVCONTAINER_IMAGE if set,
                         else the repository of the "image" line of devcontainer.json
  --tag TAG              Image tag. Default: the tag of the "image" line of devcontainer.json
  --push-by-digest FILE  Push by digest instead of loading locally (needs a buildx builder whose
                         driver is not "docker", e.g. docker-container) and write the digest to FILE
  -h, --help             Show this help message

Under GitHub Actions (GITHUB_ACTIONS=true) the image is marked "ci" with the repository URL and
the commit; otherwise it is marked "local".
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

info() {
  echo "[build-image] $*" >&2
}

cleanup() {
  if [[ -n "$BUILD_LOG" ]]; then
    rm -f "$BUILD_LOG"
  fi
}
trap cleanup EXIT

need_value() {
  [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)
      need_value "$@"
      PLATFORM="$2"
      shift 2
      ;;
    --image)
      need_value "$@"
      IMAGE_REPO="$2"
      shift 2
      ;;
    --tag)
      need_value "$@"
      IMAGE_TAG="$2"
      shift 2
      ;;
    --push-by-digest)
      need_value "$@"
      DIGEST_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "Unknown argument: $1"
      ;;
  esac
done

# --- platform
if [[ -z "$PLATFORM" ]]; then
  case "$(uname -m)" in
    x86_64|amd64) PLATFORM="linux/amd64" ;;
    arm64|aarch64) PLATFORM="linux/arm64" ;;
    *) die "Unsupported host architecture '$(uname -m)': pass --platform linux/amd64 or linux/arm64" ;;
  esac
fi
case "$PLATFORM" in
  linux/amd64|linux/arm64) ;;
  *) die "Invalid --platform '$PLATFORM': only linux/amd64 or linux/arm64" ;;
esac

# --- image: --image > WAZUH_DEVCONTAINER_IMAGE > the "image" line of devcontainer.json
[[ -f "$RUNTIME_CONFIG" ]] || die "Missing $RUNTIME_CONFIG"
[[ -f "$RECIPE_CONFIG" ]] || die "Missing $RECIPE_CONFIG"
JSON_IMAGE="$(sed -n 's/^[[:space:]]*"image":[[:space:]]*"\([^"]*\)".*$/\1/p' "$RUNTIME_CONFIG" | head -n 1)"
[[ -n "$JSON_IMAGE" ]] || die "No \"image\" line found in $RUNTIME_CONFIG"

# The tag is what follows the last ':' only if it contains no '/' (a registry port is not a tag).
JSON_REPO="$JSON_IMAGE"
JSON_TAG=""
case "${JSON_IMAGE##*:}" in
  "$JSON_IMAGE"|*/*) ;;
  *)
    JSON_TAG="${JSON_IMAGE##*:}"
    JSON_REPO="${JSON_IMAGE%:*}"
    ;;
esac

if [[ -z "$IMAGE_REPO" ]]; then
  IMAGE_REPO="${WAZUH_DEVCONTAINER_IMAGE:-$JSON_REPO}"
fi
# The digest check goes first: the ':' of "sha256:" would otherwise read as a tag.
case "$IMAGE_REPO" in
  *@*) die "Image repository '$IMAGE_REPO' carries a digest: pass the repository alone" ;;
esac
case "${IMAGE_REPO##*:}" in
  "$IMAGE_REPO"|*/*) ;;
  *) die "Image repository '$IMAGE_REPO' carries a tag: pass the repository alone and the tag with --tag" ;;
esac
if [[ -z "$IMAGE_TAG" ]]; then
  IMAGE_TAG="$JSON_TAG"
fi
[[ -n "$IMAGE_TAG" ]] || die "No tag: the \"image\" line of $RUNTIME_CONFIG has none, pass --tag"

# --- tools
command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
if command -v devcontainer >/dev/null 2>&1; then
  DC=(devcontainer)
elif command -v npx >/dev/null 2>&1; then
  DC=(npx --yes "@devcontainers/cli@${CLI_VERSION}")
else
  die "Neither devcontainer nor npx found in PATH: install Node.js (npx) or @devcontainers/cli@${CLI_VERSION}"
fi
if command -v node >/dev/null 2>&1; then
  NODE_VERSION="$(node --version 2>/dev/null || echo v0)"
  NODE_MAJOR="${NODE_VERSION#v}"
  NODE_MAJOR="${NODE_MAJOR%%.*}"
  if [[ "$NODE_MAJOR" =~ ^[0-9]+$ ]] && [[ "$NODE_MAJOR" -lt 20 ]]; then
    info "WARNING: node $NODE_VERSION is below the devcontainer CLI's requirement (>= 20); trying anyway"
  fi
fi

# --- provenance, read by image.devcontainer.json: always set, so the labels are never empty
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" && -n "${GITHUB_SHA:-}" ]] ||
    die "GITHUB_ACTIONS=true but GITHUB_SERVER_URL, GITHUB_REPOSITORY or GITHUB_SHA is empty"
  export WAZUH_DEVCONTAINER_SOURCE="ci"
  export WAZUH_DEVCONTAINER_REPO_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}"
  export WAZUH_DEVCONTAINER_REVISION="${GITHUB_SHA}"
else
  export WAZUH_DEVCONTAINER_SOURCE="local"
  export WAZUH_DEVCONTAINER_REPO_URL="https://github.com/wazuh/wazuh"
  export WAZUH_DEVCONTAINER_REVISION="local"
fi

# --no-lockfile: the CLI would otherwise write devcontainer-lock.json next to the recipe
BUILD_CMD=("${DC[@]}" build
  --workspace-folder "$WORKSPACE_DIR"
  --config "$RECIPE_CONFIG"
  --no-lockfile
  --platform "$PLATFORM"
  --cache-from "${IMAGE_REPO}:${IMAGE_TAG}"
  --cache-to type=inline)

if [[ -z "$DIGEST_FILE" ]]; then
  # --- local build: the CLI loads the image into the local Docker
  info "Building ${IMAGE_REPO}:${IMAGE_TAG} for $PLATFORM (local)"
  "${BUILD_CMD[@]}" --image-name "${IMAGE_REPO}:${IMAGE_TAG}"
  info "Done: ${IMAGE_REPO}:${IMAGE_TAG} is in the local Docker"
  exit 0
fi

# --- push by digest: the "docker" driver rejects push-by-digest
BUILDER_INFO="$(docker buildx inspect 2>&1)" || die "docker buildx inspect failed: $BUILDER_INFO"
BUILDER_NAME="$(printf '%s\n' "$BUILDER_INFO" | awk '/^Name:/ {print $2; exit}')"
BUILDER_DRIVER="$(printf '%s\n' "$BUILDER_INFO" | awk '/^Driver:/ {print $2; exit}')"
if [[ "$BUILDER_DRIVER" == "docker" || -z "$BUILDER_DRIVER" ]]; then
  die "buildx builder '${BUILDER_NAME:-unknown}' uses driver '${BUILDER_DRIVER:-unknown}', which cannot push by digest; select a docker-container builder (BUILDX_BUILDER=<name>, or: docker buildx create --driver docker-container --use)"
fi

# Fail before building (and pushing) if the digest cannot be written
: >"$DIGEST_FILE" 2>/dev/null || die "Cannot write the digest file '$DIGEST_FILE'"

BUILD_LOG="$(mktemp)"
export BUILDKIT_PROGRESS=plain
info "Building ${IMAGE_REPO} for $PLATFORM and pushing it by digest (builder '$BUILDER_NAME', driver '$BUILDER_DRIVER')"
"${BUILD_CMD[@]}" --image-name "$IMAGE_REPO" \
  --output "type=image,name=${IMAGE_REPO},push-by-digest=true,name-canonical=true,push=true" 2>&1 | tee "$BUILD_LOG"

# The pushed object is an index (image + attestations): its digest is the last "exporting manifest" line.
DIGEST="$(grep -oE 'exporting manifest( list)? sha256:[0-9a-f]{64}' "$BUILD_LOG" | tail -n 1 | awk '{print $NF}' || true)"
[[ -n "$DIGEST" ]] || die "No pushed digest found in the build output"
docker buildx imagetools inspect "${IMAGE_REPO}@${DIGEST}" >/dev/null ||
  die "${IMAGE_REPO}@${DIGEST} does not resolve in the registry"
printf '%s\n' "$DIGEST" >"$DIGEST_FILE"
info "Pushed ${IMAGE_REPO}@${DIGEST} (written to $DIGEST_FILE)"
