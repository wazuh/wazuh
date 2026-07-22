#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Move to the directory of the script
# ------------------------------------------------------------------------------
OLD_DIR=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
trap 'cd "$OLD_DIR"' EXIT
cd "$SCRIPT_DIR"

# ------------------------------------------------------------------------------
# Logging: mirror all stdout and stderr to a timestamped log file
# ------------------------------------------------------------------------------
LOG_FILE="${SCRIPT_DIR}/init.log"
: > "$LOG_FILE"
exec > >(tee "$LOG_FILE") 2>&1

echo "==========================================================="
echo "  agents/init.sh started at $(date '+%Y-%m-%d %H:%M:%S')"
echo "==========================================================="
echo ""

# ------------------------------------------------------------------------------
# CLI args
# ------------------------------------------------------------------------------
FORCE=0
for arg in "$@"; do
  case "$arg" in
    -f|--force) FORCE=1 ;;
    -h|--help)
      cat <<EOF
Usage: $0 [--force]

Downloads the four Wazuh agent installers used by docker-compose:
  - 4.x .deb (Debian/Ubuntu)
  - 4.x .rpm (CentOS/Rocky/RHEL)
  - 5.x .deb (Debian/Ubuntu) [from staging nightly]
  - 5.x .rpm (CentOS/Rocky/RHEL) [from staging nightly]

Files are saved into ./pkgs/ and are picked up by docker-compose at build time.

Options:
  --force, -f    Re-download even if the destination file already exists.
  --help,  -h    Show this help.

Required tools: curl, yq.
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
# Target architecture (autodetected; override with WAZUH_ARCH=amd64|arm64).
WAZUH_ARCH="${WAZUH_ARCH:-}"
if [ -z "$WAZUH_ARCH" ]; then
  case "$(uname -m)" in
    x86_64|amd64)  WAZUH_ARCH="amd64" ;;
    aarch64|arm64) WAZUH_ARCH="arm64" ;;
    *) echo "Unsupported architecture '$(uname -m)'. Set WAZUH_ARCH=amd64|arm64." >&2; exit 1 ;;
  esac
fi
case "$WAZUH_ARCH" in
  amd64) DEB_ARCH="amd64"; RPM_ARCH="x86_64" ;;
  arm64) DEB_ARCH="arm64"; RPM_ARCH="aarch64" ;;
  *) echo "Invalid WAZUH_ARCH='$WAZUH_ARCH'. Use amd64 or arm64." >&2; exit 1 ;;
esac

WAZUH_4X_VERSION="${WAZUH_4X_VERSION:-4.14.3-1}"

WAZUH_4X_DEB_URL="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_4X_VERSION}_${DEB_ARCH}.deb"
WAZUH_4X_RPM_URL="https://packages.wazuh.com/4.x/yum/wazuh-agent-${WAZUH_4X_VERSION}.${RPM_ARCH}.rpm"

#  WAZUH_5X_YAML_URL="https://packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/artifact-urls/artifact_urls_5.0.0-latest.yaml"
WAZUH_5X_YAML_URL="https://packages-staging.xdrsiem.wazuh.info/nightly-backup/artifact_urls_5.0.0-latest.yaml"
PKGS_DIR="${SCRIPT_DIR}/pkgs"
mkdir -p "$PKGS_DIR"

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
function need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: required command not found: $1" >&2; exit 1; }
}

function download_to() {
  local url="$1"
  local dest="$2"
  local force_dl="${3:-$FORCE}"  # optional 3rd arg overrides global FORCE

  if [[ -f "$dest" && "$force_dl" -ne 1 ]]; then
    echo "    => Already present, skipping: $(basename "$dest")"
    echo "       (use --force to re-download)"
    return 0
  fi

  echo "    => Downloading: $url"
  echo "       Saving to:   $dest"
  curl -fsSL "$url" -o "$dest.tmp"
  mv "$dest.tmp" "$dest"
  echo "    => OK ($(du -h "$dest" | awk '{print $1}'))"
}

# ------------------------------------------------------------------------------
# 4.x (production repos)
# ------------------------------------------------------------------------------
function download_4x_packages() {
  echo "==> Downloading Wazuh agent ${WAZUH_4X_VERSION} (4.x) packages..."

  download_to "$WAZUH_4X_DEB_URL" "${PKGS_DIR}/wazuh-agent_4x.deb"
  download_to "$WAZUH_4X_RPM_URL" "${PKGS_DIR}/wazuh-agent_4x.rpm"
  echo ""
}

# ------------------------------------------------------------------------------
# 5.x (staging nightly, URLs read from YAML manifest)
# ------------------------------------------------------------------------------
function download_5x_packages() {
  echo "==> Resolving Wazuh agent 5.x package URLs from manifest..."
  echo "    Manifest: $WAZUH_5X_YAML_URL"

  local tmp_yaml
  tmp_yaml="$(mktemp)"
  trap 'rm -f "$tmp_yaml"' RETURN

  curl -fsSL "$WAZUH_5X_YAML_URL" -o "$tmp_yaml"

  local deb_key="wazuh_agent_${DEB_ARCH}_deb" rpm_key="wazuh_agent_${RPM_ARCH}_rpm"
  local deb_url rpm_url
  deb_url="$(yq -r ".${deb_key}" "$tmp_yaml")"
  rpm_url="$(yq -r ".${rpm_key}" "$tmp_yaml")"

  if [[ -z "$deb_url" || "$deb_url" == "null" ]]; then
    echo "ERROR: key '${deb_key}' not found in manifest" >&2
    return 1
  fi
  if [[ -z "$rpm_url" || "$rpm_url" == "null" ]]; then
    echo "ERROR: key '${rpm_key}' not found in manifest" >&2
    return 1
  fi

  echo "    deb URL: $deb_url"
  echo "    rpm URL: $rpm_url"
  echo ""

  echo "==> Downloading Wazuh agent 5.x packages..."
  download_to "$deb_url" "${PKGS_DIR}/wazuh-agent_5x.deb" 1
  download_to "$rpm_url" "${PKGS_DIR}/wazuh-agent_5x.rpm" 1
  echo ""
}

# ==============================================================================
#                                  MAIN
# ==============================================================================
need_cmd curl
need_cmd yq

download_4x_packages
download_5x_packages

echo "==> Packages in ${PKGS_DIR}:"
ls -lh "$PKGS_DIR" | tail -n +2

echo ""
echo "==========================================================="
echo "  agents/init.sh finished at $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Log: $LOG_FILE"
echo "==========================================================="

exit 0
