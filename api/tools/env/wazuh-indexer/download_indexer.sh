#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Move to the directory of the script
# ------------------------------------------------------------------------------
OLD_DIR=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
trap 'cd "$OLD_DIR"' EXIT
cd "$SCRIPT_DIR"
ARCH="amd64"
VERSION="5.0.0"
INDEXER_PKG="wazuh-indexer_${VERSION}-latest_${ARCH}.deb"
BASE_URL="https://packages-dev.wazuh.com/nightly-backup"
# Color output for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
# ==============================================================================

find_pkg_date() {
  local pkg="$1"
  local i DATE

  log_info "Searching for $pkg in recent builds..." >&2

  for i in {0..6}; do
    DATE=$(date -u -d "-$i day" +"%Y-%m-%d")
    echo "Checking $BASE_URL/$DATE/$pkg" >&2
    if curl -s --head --fail "$BASE_URL/$DATE/$pkg" >/dev/null 2>&1; then
      echo "$DATE"
      return 0
    fi
  done
  return 1
}

download_package() {
  local pkg="$1"

  if [[ -f "$pkg" ]]; then
    log_info "$pkg already exists locally"
    return 0
  fi

  DATE="$(find_pkg_date "$pkg" || true)"
  if [[ -z "${DATE:-}" ]]; then
    log_error "$pkg not found in last 7 days of builds"
    return 1
  fi

  log_info "Downloading $pkg from $DATE..."

  # Download with progress bar
  if ! curl -L --progress-bar "$BASE_URL/$DATE/$pkg" -o "$pkg"; then
    log_error "Failed to download $pkg"
    rm -f "$pkg"  # Clean up partial download
    return 1
  fi

  log_success "Downloaded $pkg"
  return 0
}


####################################################
#                   MAIN
####################################################
if [[ -f .env ]]; then
  echo "==> Loading .env..."
  export $(grep -v '^#' .env | xargs -d '\n' || true)
fi
echo
log_info "Downloading packages..."

for PKG in "$INDEXER_PKG"; do
  if ! download_package "$PKG"; then
    log_error "Download failed. Exiting."
    exit 1
  fi
done

exit 0
