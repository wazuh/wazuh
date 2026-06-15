#!/bin/bash
# build-dev.sh — dev wrapper for building Wazuh agent packages.
#
# Runs from inside the Vagrant VM at /work/wazuh/packages.
# Uses pre-built Docker images (--dont-build-docker) and local source tree.
# eBPF probe is pulled from VPS (configured in src/Makefile: CUSTOM_RESOURCES_URL).
#
# Usage:
#   ./build-dev.sh [rpm] [deb] [-- <extra generate_package.sh args>]
#
# Examples:
#   ./build-dev.sh              # build both rpm and deb
#   ./build-dev.sh rpm          # rpm only
#   ./build-dev.sh deb          # deb only
#   ./build-dev.sh rpm -- -j 8  # rpm with 8 parallel jobs
#
# Env vars:
#   JOBS   parallel compile jobs (default: 4)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")"; pwd -P)"
OUTDIR="${SCRIPT_DIR}/output"
JOBS="${JOBS:-4}"

SYSTEMS=()
EXTRA_ARGS=()
parse_extra=0

for arg in "$@"; do
    if [[ "$arg" == "--" ]]; then
        parse_extra=1
        continue
    fi
    if [[ $parse_extra -eq 1 ]]; then
        EXTRA_ARGS+=("$arg")
    else
        case "$arg" in
            rpm|deb) SYSTEMS+=("$arg") ;;
            -h|--help)
                echo "Usage: $0 [rpm] [deb] [-- <generate_package.sh args>]"
                echo "  Default: build both rpm and deb"
                echo "  JOBS=N  parallel compile jobs (default: 4)"
                exit 0
                ;;
            *) echo "Unknown arg: $arg (use -- to pass args to generate_package.sh)"; exit 1 ;;
        esac
    fi
done

[[ ${#SYSTEMS[@]} -eq 0 ]] && SYSTEMS=(rpm deb)

mkdir -p "$OUTDIR"

for sys in "${SYSTEMS[@]}"; do
    echo ""
    echo "======================================================"
    echo " Building ${sys^^} agent package (JOBS=${JOBS})"
    echo "======================================================"
    sudo "$SCRIPT_DIR/generate_package.sh" \
        -t agent \
        --system "$sys" \
        --dont-build-docker \
        -j "$JOBS" \
        "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
done

echo ""
echo "======================================================"
echo " Output:"
echo "======================================================"
ls -lh "$OUTDIR"/*.rpm "$OUTDIR"/*.deb 2>/dev/null || echo "(no packages found in $OUTDIR)"
