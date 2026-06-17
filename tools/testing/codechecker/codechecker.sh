#!/bin/bash
###############################################################################
# codechecker.sh — CodeChecker analysis helper script.
#
# Equivalent to tools/testing/coverity/coverity.sh for the CodeChecker
# static-analysis toolchain.
#
# Usage:
#   ./codechecker.sh --build-image
#   SCAN_REF=coverity-w51-4.14.2 TARGET_REF=coverity-w52-4.14.2 \
#     SCAN_TARGET=server ./codechecker.sh --scan
#   ./codechecker.sh --clean
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(realpath "$SCRIPT_DIR/../../..")"
IMAGE="${IMAGE:-ghcr.io/wazuh/codechecker:latest}"

# Scan knobs (consumed by run_ci.sh inside the container)
SCAN_REF="${SCAN_REF:-}"
TARGET_REF="${TARGET_REF:-}"
SCAN_TARGET="${SCAN_TARGET:-server}"
SCAN_NAME="${SCAN_NAME:-}"
TARGET_NAME="${TARGET_NAME:-}"
ENABLE_CTU="${ENABLE_CTU:-1}"
RUN_INFER="${RUN_INFER:-0}"
RUN_TSAN="${RUN_TSAN:-0}"
JOBS="${JOBS:-$(nproc)}"

WORKSPACE_DIR="${WORKSPACE_DIR:-$SCRIPT_DIR/workspace}"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
CC_DB_DIR="${CC_DB_DIR:-$SCRIPT_DIR/cc-db}"

usage() {
    cat <<EOF
Usage: $0 [--build-image] [--scan] [--serve] [--clean] [--jobs N] [--help]

Options:
  --build-image   Build the CodeChecker Docker image
  --scan          Run a paired differential scan inside the Docker container
  --serve         Start the CodeChecker web UI at http://localhost:8001
                  (requires a prior --scan run; uses the saved cc-db/)
  --clean         Remove workspace/, results/, and cc-db/ directories
  --jobs N        Number of parallel jobs (default: $(nproc))
  --help          Show this help

Scan environment variables (required for --scan):
  SCAN_REF        Base ref (tag or SHA)                        [required]
  TARGET_REF      Target ref (tag or SHA)                      [required]
  SCAN_TARGET     Wazuh make target (default: server)
  SCAN_NAME       Dashboard run name for base  (default: wazuh-\$SCAN_REF)
  TARGET_NAME     Dashboard run name for target (default: wazuh-\$TARGET_REF)
  ENABLE_CTU      Cross-TU analysis (default: 1; set 0 to disable)
  RUN_INFER       Infer/RacerD static race scan (default: 0; adds ~20 min)
  RUN_TSAN        ThreadSanitizer (default: 0; requires vm.mmap_rnd_bits<=28)
  IMAGE           Docker image to use (default: ghcr.io/wazuh/codechecker:latest)

Example:
  SCAN_REF=coverity-w51-4.14.2 \\
  TARGET_REF=coverity-w52-4.14.2 \\
  SCAN_TARGET=server \\
  $0 --scan
  $0 --serve    # open http://localhost:8001 in your browser
EOF
}

build_image() {
    echo "[*] Building Docker image: $IMAGE"
    docker build -t "$IMAGE" "$SCRIPT_DIR"
    echo "[*] Image built: $IMAGE"
}

do_scan() {
    [ -n "$SCAN_REF" ]   || { echo "Error: SCAN_REF is required for --scan"; usage; exit 1; }
    [ -n "$TARGET_REF" ] || { echo "Error: TARGET_REF is required for --scan"; usage; exit 1; }

    mkdir -p "$WORKSPACE_DIR" "$RESULTS_DIR" "$CC_DB_DIR"

    echo "[*] Starting CodeChecker scan"
    echo "    base:    ${SCAN_NAME:-wazuh-$SCAN_REF} ($SCAN_REF)"
    echo "    target:  ${TARGET_NAME:-wazuh-$TARGET_REF} ($TARGET_REF)"
    echo "    build:   $SCAN_TARGET  jobs=$JOBS"
    echo "    CTU=$ENABLE_CTU  INFER=$RUN_INFER  TSAN=$RUN_TSAN"

    docker run --rm \
        -v "$WORKSPACE_DIR:/workspace" \
        -v "$RESULTS_DIR:/results" \
        -v "$CC_DB_DIR:/tmp/cc-db" \
        -e SCAN_REF="$SCAN_REF" \
        -e TARGET_REF="$TARGET_REF" \
        -e SCAN_TARGET="$SCAN_TARGET" \
        -e SCAN_NAME="$SCAN_NAME" \
        -e TARGET_NAME="$TARGET_NAME" \
        -e ENABLE_CTU="$ENABLE_CTU" \
        -e RUN_INFER="$RUN_INFER" \
        -e RUN_TSAN="$RUN_TSAN" \
        -e JOBS="$JOBS" \
        "$IMAGE" \
        bash /cc/run_ci.sh

    echo "[*] Scan complete."
    echo "    HTML diff:    $RESULTS_DIR/diff_new_html/index.html"
    echo "    Full report:  $RESULTS_DIR/full_report_html/index.html"
    echo "    Dashboard:    run '$0 --serve' then open http://localhost:8001"
}

do_serve() {
    [ -d "$CC_DB_DIR" ] || { echo "Error: no cc-db found — run --scan first"; exit 1; }
    echo "[*] Starting CodeChecker server"
    echo "    DB:  $CC_DB_DIR"
    echo "    URL: http://localhost:8001"
    echo "    Press Ctrl-C to stop."
    docker run --rm -it \
        -v "$CC_DB_DIR:/tmp/cc-db" \
        -p 8001:8001 \
        "$IMAGE" \
        CodeChecker server --workspace /tmp/cc-db --host 0.0.0.0 --port 8001
}

do_clean() {
    echo "[*] Removing workspace/, results/, and cc-db/"
    rm -rf "$SCRIPT_DIR/workspace" "$SCRIPT_DIR/results" "$SCRIPT_DIR/cc-db"
    echo "[*] Clean complete."
}

if [ $# -eq 0 ]; then usage; exit 1; fi

while [ $# -gt 0 ]; do
    case "$1" in
        --build-image) build_image ;;
        --scan)        do_scan ;;
        --serve)       do_serve ;;
        --clean)       do_clean ;;
        --jobs)
            shift
            [[ "${1:-}" =~ ^[0-9]+$ ]] || { echo "Error: --jobs requires a number"; exit 1; }
            JOBS="$1"
            ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done
