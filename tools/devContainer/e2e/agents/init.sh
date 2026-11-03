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
# Logging: mirror stdout and stderr to init.log (appended: one run must not erase the previous)
# ------------------------------------------------------------------------------
LOG_FILE="${SCRIPT_DIR}/init.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "==========================================================="
echo "  agents/init.sh started at $(date '+%Y-%m-%d %H:%M:%S')"
echo "==========================================================="
echo ""

# ------------------------------------------------------------------------------
# CLI args
# ------------------------------------------------------------------------------
FORCE=0
CHECK=0
for arg in "$@"; do
  case "$arg" in
    -f|--force) FORCE=1 ;;
    --check) CHECK=1 ;;
    -h|--help)
      cat <<USAGE
Usage: $0 [--force] [--check]

Downloads the four Wazuh agent installers used by docker-compose into ./pkgs/:
  - 4.x .deb / .rpm from packages.wazuh.com (WAZUH_4X_VERSION, default 4.14.3-1)
  - 5.x .deb / .rpm from the staging nightly manifests (primary, then the nightly-backup fallback
    — the same pair e2e/init.sh uses for indexer and dashboard)
for this machine's architecture (WAZUH_ARCH=amd64|arm64 overrides the detection), saved under the
fixed names wazuh-agent_{4x,5x}.{deb,rpm} that the Dockerfiles install by exact name.

A 5.x package already in pkgs/ is re-downloaded when its size differs from the remote one (the
"latest" file is rebuilt every night; an old copy silently lacks new agent features such as the
enrollment-token bootstrap). 4.x packages are versioned and only re-downloaded with --force.
The names are fixed, so the URL each package came from is kept in pkgs/<name>.url: a package
fetched from another URL (another WAZUH_4X_VERSION or WAZUH_ARCH, or a copy without that record)
is STALE and re-downloaded.

Options:
  --check        Do not download: report CURRENT / STALE / MISSING per package and exit 3 when
                 anything is stale or missing (callers decide whether to run without --check).
  --force, -f    Re-download every package even when present and current.
  --help,  -h    Show this help.

Required tools: curl.
USAGE
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
WAZUH_4X_VERSION="${WAZUH_4X_VERSION:-4.14.3-1}"

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
WAZUH_4X_DEB_URL="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_4X_VERSION}_${DEB_ARCH}.deb"
WAZUH_4X_RPM_URL="https://packages.wazuh.com/4.x/yum/wazuh-agent-${WAZUH_4X_VERSION}.${RPM_ARCH}.rpm"

WAZUH_5X_PRIMARY_MANIFEST_URL="${WAZUH_5X_PRIMARY_MANIFEST_URL:-https://packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/artifact-urls/artifact_urls_5.0.0-latest.yaml}"
WAZUH_5X_FALLBACK_MANIFEST_URL="${WAZUH_5X_FALLBACK_MANIFEST_URL:-https://packages-staging.xdrsiem.wazuh.info/nightly-backup/artifact_urls_5.0.0-latest.yaml}"

PKGS_DIR="${SCRIPT_DIR}/pkgs"
mkdir -p "$PKGS_DIR"
STALE=0

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
function need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: required command not found: $1" >&2; exit 1; }
}

# Value of a top-level "key: value" line of a flat YAML manifest (sed, so no yq dependency).
function yaml_value() {
  local key="$1" file="$2"
  sed -n "s/^${key}:[[:space:]]*//p" "$file" | head -n 1 | tr -d '"'"'"
}

function remote_size() {  # Content-Length of a URL, empty when unknown
  curl -fsSIL "$1" 2>/dev/null | tr -d '\r' | awk 'tolower($1)=="content-length:" {v=$2} END {print v}'
}

# download_to <url> <dest> <policy>   policy: versioned (keep if present) | latest (refresh when the size differs)
# <dest>.url records the URL <dest> was fetched from: the names do not carry version or architecture.
function download_to() {
  local url="$1" dest="$2" policy="$3"
  local name; name=$(basename "$dest")
  local rsize lsize="" lurl=""
  rsize=$(remote_size "$url")
  [[ -f "$dest" ]] && lsize=$(stat -c %s "$dest")
  [[ -f "$dest.url" ]] && lurl=$(<"$dest.url")

  local state why=""
  if [[ ! -f "$dest" ]]; then state=MISSING
  elif [[ "$lurl" != "$url" ]]; then state=STALE; why=", fetched from ${lurl:-an unrecorded URL}"
  elif [[ "$policy" == latest && -n "$rsize" && "$rsize" != "$lsize" ]]; then state=STALE
  else state=CURRENT; fi

  if (( CHECK == 1 )); then
    printf '    %-8s %s (local %s bytes, remote %s bytes%s)\n' "$state" "$name" "${lsize:-0}" "${rsize:-?}" "$why"
    [[ "$state" == CURRENT ]] || STALE=1
    return 0
  fi

  if [[ "$state" == CURRENT && "$FORCE" -ne 1 ]]; then
    echo "    => $name: present and current, skipping (use --force to re-download)"
    return 0
  fi

  echo "    => Downloading: $url"
  echo "       Saving to:   $dest"
  curl -fsSL "$url" -o "$dest.tmp"
  mv "$dest.tmp" "$dest"
  printf '%s\n' "$url" > "$dest.url"
  echo "    => OK ($(du -h "$dest" | awk '{print $1}'))"
}

# ------------------------------------------------------------------------------
# 4.x (production repos)
# ------------------------------------------------------------------------------
function download_4x_packages() {
  echo "==> Wazuh agent ${WAZUH_4X_VERSION} (4.x, ${WAZUH_ARCH}) packages..."
  download_to "$WAZUH_4X_DEB_URL" "${PKGS_DIR}/wazuh-agent_4x.deb" versioned
  download_to "$WAZUH_4X_RPM_URL" "${PKGS_DIR}/wazuh-agent_4x.rpm" versioned
  echo ""
}

# ------------------------------------------------------------------------------
# 5.x (staging nightly, URLs read from the YAML manifests)
# ------------------------------------------------------------------------------
# The primary manifest is rewritten while the nightly runs and can miss keys for hours (seen on
# 2026-09-17: only the installation-assistant keys were there); the backup keeps the previous
# complete set. Resolve each key against the primary first, then the fallback — per key, like
# e2e/init.sh does for indexer and dashboard.
function fetch_manifests() {  # $1 $2: destination files for primary and fallback (either may end up empty)
  curl -fsSL "$WAZUH_5X_PRIMARY_MANIFEST_URL" -o "$1" 2>/dev/null || : > "$1"
  curl -fsSL "$WAZUH_5X_FALLBACK_MANIFEST_URL" -o "$2" 2>/dev/null || : > "$2"
  [[ -s "$1" || -s "$2" ]]
}

function resolve_key() {  # resolve_key <key> <primary> <fallback>  → prints the URL, reports the source on stderr
  local v
  v="$(yaml_value "$1" "$2")"
  if [[ -n "$v" ]]; then echo "    $1: primary manifest" >&2; echo "$v"; return 0; fi
  v="$(yaml_value "$1" "$3")"
  if [[ -n "$v" ]]; then echo "    $1: nightly-backup manifest (missing from the primary)" >&2; echo "$v"; return 0; fi
  return 1
}

function download_5x_packages() {
  echo "==> Wazuh agent 5.x packages (nightly manifests)..."
  local m_primary m_fallback
  m_primary="$(mktemp)"; m_fallback="$(mktemp)"
  trap 'rm -f "$m_primary" "$m_fallback"' RETURN
  fetch_manifests "$m_primary" "$m_fallback" || { echo "ERROR: neither 5.x manifest could be fetched" >&2; return 1; }
  echo "    primary:  $WAZUH_5X_PRIMARY_MANIFEST_URL ($([[ -s "$m_primary" ]] && echo fetched || echo unavailable))"
  echo "    fallback: $WAZUH_5X_FALLBACK_MANIFEST_URL ($([[ -s "$m_fallback" ]] && echo fetched || echo unavailable))"

  local deb_url rpm_url
  local deb_key="wazuh_agent_${DEB_ARCH}_deb" rpm_key="wazuh_agent_${RPM_ARCH}_rpm"
  deb_url="$(resolve_key "$deb_key" "$m_primary" "$m_fallback")" || { echo "ERROR: key '${deb_key}' in neither manifest" >&2; return 1; }
  rpm_url="$(resolve_key "$rpm_key" "$m_primary" "$m_fallback")" || { echo "ERROR: key '${rpm_key}' in neither manifest" >&2; return 1; }
  echo "    deb URL: $deb_url"
  echo "    rpm URL: $rpm_url"

  download_to "$deb_url" "${PKGS_DIR}/wazuh-agent_5x.deb" latest
  download_to "$rpm_url" "${PKGS_DIR}/wazuh-agent_5x.rpm" latest
  echo ""
}

# ==============================================================================
#                                  MAIN
# ==============================================================================
need_cmd curl

download_4x_packages
download_5x_packages

if (( CHECK == 1 )); then
  if (( STALE == 1 )); then
    echo "==> Some packages are STALE or MISSING: run $0 (or --force) before docker compose build."
    exit 3
  fi
  echo "==> All packages present and current."
  exit 0
fi

echo "==> Packages in ${PKGS_DIR}:"
ls -lh "$PKGS_DIR" | tail -n +2

echo ""
echo "==========================================================="
echo "  agents/init.sh finished at $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Log: $LOG_FILE"
echo "==========================================================="

exit 0
