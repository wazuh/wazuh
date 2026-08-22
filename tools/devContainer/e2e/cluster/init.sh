#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Resolve the wazuh-manager artifact used to build the cluster node image into
# node/pkg/, according to WAZUH_MANAGER_SOURCE:
#
#   manifest  (default)  Download the nightly manager package for the target arch
#                        from the staging manifest.
#   local                Use a local .deb given in WAZUH_MANAGER_DEB.
#   source               Package the manager already built and installed on this
#                        host (WAZUH_HOME, default /var/wazuh-manager) into a tree
#                        tarball. Build it first with the devContainer make tasks.
# ------------------------------------------------------------------------------
OLD_DIR=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
trap 'cd "$OLD_DIR"' EXIT
cd "$SCRIPT_DIR"

SOURCE="${WAZUH_MANAGER_SOURCE:-manifest}"
MANIFEST_URL="${WAZUH_MANIFEST_URL:-https://packages-staging.xdrsiem.wazuh.info/nightly-backup/artifact_urls_5.0.0-latest.yaml}"
PKG_DIR="${SCRIPT_DIR}/node/pkg"

function need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: required command not found: $1" >&2; exit 1; }; }

function resolve_arch() {
  local arch="${WAZUH_ARCH:-}"
  if [[ -z "$arch" ]]; then
    case "$(uname -m)" in
      x86_64|amd64)  arch="amd64" ;;
      aarch64|arm64) arch="arm64" ;;
      *) echo "Unsupported architecture '$(uname -m)'. Set WAZUH_ARCH=amd64|arm64." >&2; exit 1 ;;
    esac
  fi
  case "$arch" in amd64|arm64) DEB_ARCH="$arch" ;; *) echo "Invalid WAZUH_ARCH='$arch'." >&2; exit 1 ;; esac
}

function reset_pkg() { mkdir -p "$PKG_DIR"; rm -f "$PKG_DIR"/*.deb "$PKG_DIR"/*.tar.gz 2>/dev/null || true; }

function from_manifest() {
  need_cmd curl; need_cmd yq; resolve_arch
  local key="wazuh_manager_${DEB_ARCH}_deb" url
  echo "==> [manifest] Resolving '${key}'"
  url="$(curl -fsSL "$MANIFEST_URL" | yq -r ".${key}")"
  [[ -n "$url" && "$url" != "null" ]] || { echo "ERROR: '${key}' not found in manifest" >&2; exit 1; }
  reset_pkg
  echo "==> Downloading ${url}"
  curl -fsSL "$url" -o "${PKG_DIR}/$(basename "$url")"
}

function from_local() {
  : "${WAZUH_MANAGER_DEB:?set WAZUH_MANAGER_DEB to a local wazuh-manager .deb path}"
  [[ -f "$WAZUH_MANAGER_DEB" ]] || { echo "ERROR: file not found: $WAZUH_MANAGER_DEB" >&2; exit 1; }
  reset_pkg
  echo "==> [local] Using ${WAZUH_MANAGER_DEB}"
  cp "$WAZUH_MANAGER_DEB" "${PKG_DIR}/$(basename "$WAZUH_MANAGER_DEB")"
}

function from_source() {
  local home="${WAZUH_HOME:-/var/wazuh-manager}"
  [[ -x "${home}/bin/wazuh-manager-control" ]] || {
    echo "ERROR: no manager install found at ${home}. Build it first with the devContainer" >&2
    echo "       'Build MANAGER' task, then re-run with WAZUH_MANAGER_SOURCE=source." >&2
    exit 1
  }
  reset_pkg
  echo "==> [source] Packaging ${home} into the node image context"
  # Exclude the master's identity/state (the worker gets its own via cluster sync
  # and the entrypoint) and volatile paths that make tar exit 1 ("file changed as
  # we read it") on a live install; tolerate that specific exit code.
  local base; base="$(basename "$home")"
  tar -C "$(dirname "$home")" --warning=no-file-changed \
      --exclude="${base}/logs" --exclude="${base}/queue" --exclude="${base}/var" \
      --exclude="${base}/etc/client.keys" --exclude="${base}/etc/authd.pass" \
      -czf "${PKG_DIR}/wazuh-manager-tree.tar.gz" "$base" || [ $? -eq 1 ]
}

function ensure_cluster_key() {
  local env_file="${SCRIPT_DIR}/.env"
  if [[ -f "$env_file" ]] && grep -q '^WAZUH_CLUSTER_KEY=' "$env_file"; then
    echo "==> Cluster key already present in ${env_file}"
    return 0
  fi
  need_cmd openssl
  printf 'WAZUH_CLUSTER_KEY=%s\n' "$(openssl rand -hex 16)" >> "$env_file"
  echo "==> Generated cluster key in ${env_file}"
}

case "$SOURCE" in
  manifest) from_manifest ;;
  local)    from_local ;;
  source)   from_source ;;
  *) echo "Invalid WAZUH_MANAGER_SOURCE='${SOURCE}'. Use manifest|local|source." >&2; exit 1 ;;
esac

ensure_cluster_key

echo "==> node/pkg:"
ls -lh "$PKG_DIR" | tail -n +2
