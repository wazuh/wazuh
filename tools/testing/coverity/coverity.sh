#!/bin/bash

set -euo pipefail

# Defaults
PROJECT="${PROJECT:-wazuh}"
COVERITY_TOKEN="${COVERITY_TOKEN:-}"
EMAIL="${EMAIL:-devel@wazuh.com}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(realpath "$SCRIPT_DIR/../../..")"
COVERITY_DIR="$SCRIPT_DIR"
IMAGE="ghcr.io/wazuh/coverity-scan:latest"
COV_DIR="$ROOT_DIR/cov-int"
TARBALL="$ROOT_DIR/wazuh.tgz"
TOOL_TGZ="$COVERITY_DIR/coverity_tool.tgz"
JOBS="$(nproc)"

# Extract version and description
VERSION="$(jq -r '.version + "-" + .stage' "$ROOT_DIR/VERSION.json")"
BRANCH="$(git -C "$ROOT_DIR" describe --tags --exact-match 2>/dev/null || git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD)"
DESCRIPTION="Version $VERSION - Git ref $BRANCH"

# Usage
function usage() {
    cat <<EOF
Usage: $0 [--build-image] [--build] [--upload] [--clean] [--jobs N] [--help]

Options:
  --build-image   Build the Docker image and download Coverity tool (exits after)
  --build         Run Coverity analysis and generate wazuh.tgz
  --upload        Upload wazuh.tgz to Coverity
  --clean         Remove generated files (cov-int/ and wazuh.tgz)
  --jobs N        Number of parallel jobs to use for build (default: $(nproc))
  --help          Show this help

No arguments: runs both --build and --upload

Environment variables:
  PROJECT         Coverity project name (default: "wazuh")
  COVERITY_TOKEN  Coverity token (required for --build-image or --upload)
  EMAIL           Email associated with Coverity account (default: devel@wazuh.com)
EOF
}

# Parse arguments
DO_BUILD_IMAGE=false
DO_BUILD=false
DO_UPLOAD=false
DO_CLEAN=false

if [[ $# -eq 0 ]]; then
    DO_BUILD=true
    DO_UPLOAD=true
else
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --build-image) DO_BUILD_IMAGE=true ;;
            --build)       DO_BUILD=true ;;
            --upload)      DO_UPLOAD=true ;;
            --clean)       DO_CLEAN=true ;;
            --jobs)
                shift
                if [[ $# -eq 0 || ! "$1" =~ ^[0-9]+$ ]]; then
                    echo "Error: --jobs requires a numeric argument"
                    exit 1
                fi
                JOBS="$1"
                ;;
            --help) usage; exit 0 ;;
            *) echo "Unknown option: $1"; usage; exit 1 ;;
        esac
        shift
    done
fi

# Always clean up coverity_tool.tgz if it gets created
trap '[[ -f "$TOOL_TGZ" ]] && rm -f "$TOOL_TGZ"' EXIT

# --build-image: build and exit
if $DO_BUILD_IMAGE; then
    if [[ -z "$COVERITY_TOKEN" ]]; then
        echo "Error: TOKEN must be set for --build-image"
        exit 1
    fi

    echo "[*] Downloading Coverity tool..."
    wget -q https://scan.coverity.com/download/linux64 \
        --post-data "token=${COVERITY_TOKEN}&project=wazuh%2F${PROJECT}" \
        -O "$TOOL_TGZ"

    echo "[*] Building Docker image..."
    docker build -t "$IMAGE" "$COVERITY_DIR"

    echo "[*] Image built successfully."
    exit 0
fi

# --build
if $DO_BUILD; then
    echo "[*] Cleaning source directory..."
    make -C "$ROOT_DIR/src" clean-internals
    make -C "$ROOT_DIR/src" clean-windows
    rm -rf "$COV_DIR"

    echo "[*] Running Coverity analysis with Docker (jobs=$JOBS)..."
    docker run --rm \
        -v "$ROOT_DIR:/src" \
        -w /src \
        -u "$(id -u):$(id -g)" \
        "$IMAGE" \
        make -C src TARGET=server COVERITY=YES -j"$JOBS"

    echo "[*] Creating tarball..."
    tar czf "$TARBALL" -C "$ROOT_DIR" cov-int
fi

# --clean
if $DO_CLEAN; then
    echo "[*] Cleaning generated files..."
    rm -rf "$COV_DIR"
    rm -f "$TARBALL"
    echo "[*] Cleanup completed."
    exit 0
fi

# --upload
if $DO_UPLOAD; then
    if [[ -z "$COVERITY_TOKEN" ]]; then
        echo "Error: COVERITY_TOKEN must be set for --upload"
        exit 1
    fi

    if [[ ! -f "$TARBALL" ]]; then
        echo "Error: $TARBALL not found. Did you run with --build?"
        exit 1
    fi

    echo "[*] Uploading to Coverity..."

    response=$(curl -s -w "%{http_code}" \
        --form token="$COVERITY_TOKEN" \
        --form email="$EMAIL" \
        --form file=@"$TARBALL" \
        --form version="$VERSION" \
        --form description="$DESCRIPTION" \
        "https://scan.coverity.com/builds?project=wazuh%2F${PROJECT}")

    body=${response::-3}
    code=${response: -3}

    echo $body

    if [[ $code -ge 400 ]]; then
        exit 1
    fi

    echo "[*] Upload complete."
fi
