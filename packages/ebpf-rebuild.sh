#!/bin/bash
# ebpf-rebuild.sh — recompile modern.bpf.c on the VM and upload to VPS.
#
# Run from inside the Vagrant VM at /work/wazuh/packages (or anywhere).
# Requires: clang (BPF-capable, e.g. clang-15), cmake >= 3.12, make, scp.
#
# Flow:
#   1. Download libbpf-bootstrap SOURCE tarball if not present (from VPS or official)
#   2. Copy modern.bpf.c from wazuh source tree into the libbpf-bootstrap source dir
#   3. cmake configure + build libbpf_external target on the VM (uses host clang)
#   4. Package libbpf-bootstrap/build/ → libbpf-bootstrap.tar.gz
#   5. Upload to VPS via SCP
#
# Configuration (edit or export before running):
#   VPS_SSH        SSH destination, e.g. "user@yourmum.duckdns.org"
#   VPS_WEB_ROOT   Web root on the VPS where HTTP server serves /deps/
#                  e.g. "/srv/deps"  → uploaded to VPS_WEB_ROOT/libraries/linux/amd64/
#   VPS_SSH_PORT   SSH port (default: 22)
#   JOBS           parallel build jobs (default: nproc)

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────
VPS_SSH="${VPS_SSH:-user@yourmum.duckdns.org}"
VPS_WEB_ROOT="${VPS_WEB_ROOT:-/srv/deps}"
VPS_SSH_PORT="${VPS_SSH_PORT:-22}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

SCRIPT_DIR="$(cd "$(dirname "$0")"; pwd -P)"
WAZUH_ROOT="$(cd "$SCRIPT_DIR/.."; pwd -P)"
SRC_DIR="${WAZUH_ROOT}/src"
EXTERNAL_DIR="${SRC_DIR}/external"
LIBBPF_DIR="${EXTERNAL_DIR}/libbpf-bootstrap"
EBPF_SRC="${WAZUH_ROOT}/src/syscheckd/src/ebpf/src/modern.bpf.c"
OUTPUT_TARBALL="${SCRIPT_DIR}/output/libbpf-bootstrap.tar.gz"

# Where modern.bpf.c lives inside libbpf-bootstrap source tree.
# Adjust if Wazuh's fork puts it elsewhere (e.g. "src/modern.bpf.c").
EBPF_DEST_IN_LIBBPF="src/modern.bpf.c"

log()  { echo "[ebpf-rebuild] $*"; }
die()  { echo "[ebpf-rebuild] ERROR: $*" >&2; exit 1; }

# ─── Sanity checks ────────────────────────────────────────────────────────────
[[ -f "$EBPF_SRC" ]] || die "modern.bpf.c not found at $EBPF_SRC"
command -v clang  >/dev/null 2>&1 || die "clang not found — install clang-15 or set PATH"
command -v cmake  >/dev/null 2>&1 || die "cmake not found"
command -v scp    >/dev/null 2>&1 || die "scp not found"

mkdir -p "${SCRIPT_DIR}/output"

# ─── Step 1: Ensure libbpf-bootstrap source is present ───────────────────────
if [[ ! -d "$LIBBPF_DIR" ]]; then
    log "libbpf-bootstrap source not found, downloading..."

    # Try VPS first (same source tarball path as official)
    DEPS_VERSION="$(sed -n 's/^DEPS_VERSION[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*/\1/p' "${SRC_DIR}/Makefile" | head -n1)"
    [[ -n "$DEPS_VERSION" ]] || die "could not read DEPS_VERSION from src/Makefile"

    VPS_SRC_URL="https://yourmum.duckdns.org:30035/deps/libraries/sources/libbpf-bootstrap.tar.gz"
    OFFICIAL_SRC_URL="https://packages.wazuh.com/deps/${DEPS_VERSION}/libraries/sources/libbpf-bootstrap.tar.gz"
    TMP_TAR="/tmp/libbpf-bootstrap-src.tar.gz"

    log "Trying VPS source: $VPS_SRC_URL"
    if curl -k -fsSLo "$TMP_TAR" "$VPS_SRC_URL" 2>/dev/null; then
        log "Downloaded from VPS"
    else
        log "VPS failed, trying official: $OFFICIAL_SRC_URL"
        curl -fsSLo "$TMP_TAR" "$OFFICIAL_SRC_URL" || die "Could not download libbpf-bootstrap source"
        log "Downloaded from official"
    fi

    mkdir -p "$EXTERNAL_DIR"
    tar -xf "$TMP_TAR" -C "$EXTERNAL_DIR"
    rm -f "$TMP_TAR"

    # Handle versioned top-level dir (e.g. libbpf-bootstrap-1.2.3/ → libbpf-bootstrap/)
    extracted="$(ls -d "${EXTERNAL_DIR}"/libbpf-bootstrap*/ 2>/dev/null | grep -v "^${LIBBPF_DIR}/$" | head -n1 || true)"
    if [[ -n "$extracted" ]]; then
        mv "$extracted" "$LIBBPF_DIR"
    fi

    [[ -d "$LIBBPF_DIR" ]] || die "libbpf-bootstrap directory not found after extraction"
    log "Extracted to $LIBBPF_DIR"
fi

# ─── Step 2: Copy updated modern.bpf.c into libbpf-bootstrap ─────────────────
DEST="${LIBBPF_DIR}/${EBPF_DEST_IN_LIBBPF}"
log "Copying modern.bpf.c → $DEST"
mkdir -p "$(dirname "$DEST")"
cp "$EBPF_SRC" "$DEST"

# ─── Step 3: cmake configure + build libbpf_external ─────────────────────────
log "Configuring wazuh cmake (TARGET=agent)..."
mkdir -p "${SRC_DIR}/build"
cmake -S "$SRC_DIR" -B "${SRC_DIR}/build" -DTARGET=agent -DCMAKE_BUILD_TYPE=Release \
    2>&1 | grep -E "(CMake|libbpf|ERROR|error)" || true

log "Building libbpf_external with $JOBS jobs..."
cmake --build "${SRC_DIR}/build" \
    --target libbpf_external \
    --parallel "$JOBS"

BPF_OBJ="${LIBBPF_DIR}/build/modern.bpf.o"
[[ -f "$BPF_OBJ" ]] || die "modern.bpf.o not produced at $BPF_OBJ — check cmake output"
log "modern.bpf.o built: $(ls -lh "$BPF_OBJ")"

# ─── Step 4: Package ─────────────────────────────────────────────────────────
log "Packaging libbpf-bootstrap → $OUTPUT_TARBALL"
# Tarball root: libbpf-bootstrap/ so the extract path matches what make deps expects
tar -czf "$OUTPUT_TARBALL" \
    -C "$EXTERNAL_DIR" \
    libbpf-bootstrap/
log "Tarball: $(ls -lh "$OUTPUT_TARBALL")"

# ─── Step 5: Upload to VPS ────────────────────────────────────────────────────
VPS_DEST_DIR="${VPS_WEB_ROOT}/libraries/linux/amd64"
log "Uploading to ${VPS_SSH}:${VPS_DEST_DIR}/ (port ${VPS_SSH_PORT})"
ssh -p "$VPS_SSH_PORT" "$VPS_SSH" "mkdir -p '${VPS_DEST_DIR}'"
scp -P "$VPS_SSH_PORT" "$OUTPUT_TARBALL" "${VPS_SSH}:${VPS_DEST_DIR}/libbpf-bootstrap.tar.gz"

log ""
log "Done. Re-run ./build-dev.sh to pick up the new probe."
