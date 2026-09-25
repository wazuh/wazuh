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

function reset_pkg() { mkdir -p "$PKG_DIR"; rm -f "$PKG_DIR"/*.deb "$PKG_DIR"/*.tar.gz "$PKG_DIR"/*.tar.gz.tmp "$PKG_DIR"/wazuh-manager.ids 2>/dev/null || true; }

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
  # A relative path is the caller's, not this script's (it cd's to its own dir).
  [[ "$WAZUH_MANAGER_DEB" = /* ]] || WAZUH_MANAGER_DEB="${OLD_DIR}/${WAZUH_MANAGER_DEB}"
  [[ -f "$WAZUH_MANAGER_DEB" ]] || { echo "ERROR: file not found: $WAZUH_MANAGER_DEB" >&2; exit 1; }
  # Copy it aside first: the package may already live in node/pkg/ (a nightly
  # downloaded by an earlier run), which reset_pkg empties.
  local staged; staged="$(mktemp)"
  cp "$WAZUH_MANAGER_DEB" "$staged"
  reset_pkg
  echo "==> [local] Using ${WAZUH_MANAGER_DEB}"
  mv "$staged" "${PKG_DIR}/$(basename "$WAZUH_MANAGER_DEB")"
  chmod 644 "${PKG_DIR}/$(basename "$WAZUH_MANAGER_DEB")"
}

function from_source() {
  local requested="${WAZUH_HOME:-/var/wazuh-manager}" home
  # The worker runs the tree at /var/wazuh-manager, and an install is not
  # relocatable: the engine store records absolute paths (data/store/geo/mmdb/0
  # names <home>/data/mmdb/*.mmdb), so a snapshot of another home would give
  # workers that look healthy and have no GeoIP data. Only that home is taken,
  # and from here on only its canonical spelling is used (tar takes its basename:
  # /var/wazuh-manager/. would archive ".").
  home="$(realpath -m "$requested")"
  if [[ "$home" != /var/wazuh-manager ]]; then
    echo "ERROR: source mode snapshots an install at /var/wazuh-manager only (got WAZUH_HOME=${requested})." >&2
    echo "       The worker runs it from that path, and the install records absolute paths under its home." >&2
    exit 1
  fi
  [[ -x "${home}/bin/wazuh-manager-control" ]] || {
    echo "ERROR: no manager install found at ${home}. Build it first with the devContainer" >&2
    echo "       'Build MANAGER' task, then re-run with WAZUH_MANAGER_SOURCE=source." >&2
    exit 1
  }
  # A running manager rewrites data/ (the engine's RocksDB stores and IOC metadata)
  # while tar reads it, and a snapshot taken mid-write gives a worker that looks
  # healthy with missing detection data. Snapshot a stopped manager only;
  # setup-master.sh starts it again.
  # status exits 1 as soon as one daemon is down, so read its output apart from its
  # exit code (with pipefail, a pipeline would hide a partially running manager).
  local status; status="$("${home}/bin/wazuh-manager-control" status 2>/dev/null)" || true
  if grep -q ' is running' <<<"$status"; then
    echo "ERROR: the manager at ${home} is running. Stop it for the snapshot:" >&2
    echo "       sudo ${home}/bin/wazuh-manager-control stop   (setup-master.sh starts it again)" >&2
    exit 1
  fi
  reset_pkg
  echo "==> [source] Packaging ${home} into the node image context"
  # Exclude the master's identity/state (the worker gets its own via cluster sync
  # and the entrypoint) and the runtime dirs the worker recreates. The archive is
  # published only once tar succeeded.
  local base; base="$(basename "$home")"
  tar -C "$(dirname "$home")" \
      --exclude="${base}/logs" --exclude="${base}/queue" --exclude="${base}/var" \
      --exclude="${base}/etc/client.keys" --exclude="${base}/etc/authd.pass" \
      -czf "${PKG_DIR}/wazuh-manager-tree.tar.gz.tmp" "$base"
  mv "${PKG_DIR}/wazuh-manager-tree.tar.gz.tmp" "${PKG_DIR}/wazuh-manager-tree.tar.gz"
  # The image creates wazuh-manager with these ids before extracting the tree (node/Dockerfile).
  printf 'WAZUH_UID=%s\nWAZUH_GID=%s\n' "$(id -u wazuh-manager)" "$(id -g wazuh-manager)" > "${PKG_DIR}/wazuh-manager.ids"
}

# Settings the master and the workers must share (cluster key and name) have one
# source of truth, cluster/.env, which compose reads with --env-file. An exported
# value replaces the stored one (compose gives the exported variable precedence
# over the env file, so the master must use it too); otherwise the stored value is
# reused; otherwise <default> is stored. The file is written 0600 (it holds the
# key). cluster/init.sh and setup-master.sh resolve them with this same function.
function resolve_cluster_setting() {  # resolve_cluster_setting <env file> <VAR> <default>  → REPLY
  local env_file="$1" var="$2" default="$3" stored=""
  [[ -f "$env_file" ]] && stored="$(grep -m1 "^${var}=" "$env_file" | cut -d= -f2-)" || true
  if [[ -n "${!var:-}" ]]; then REPLY="${!var}"
  elif [[ -n "$stored" ]]; then REPLY="$stored"
  else REPLY="$default"; fi
  if [[ "$REPLY" != "$stored" ]]; then
    ( umask 077; { grep -v "^${var}=" "$env_file" 2>/dev/null || true; printf '%s=%s\n' "$var" "$REPLY"; } > "$env_file.new" )
    mv "$env_file.new" "$env_file"
    echo "==> ${var} $([[ -n "$stored" ]] && echo replaced || echo stored) in ${env_file}"
  fi
}

case "$SOURCE" in
  manifest) from_manifest ;;
  local)    from_local ;;
  source)   from_source ;;
  *) echo "Invalid WAZUH_MANAGER_SOURCE='${SOURCE}'. Use manifest|local|source." >&2; exit 1 ;;
esac

need_cmd openssl
resolve_cluster_setting "${SCRIPT_DIR}/.env" WAZUH_CLUSTER_KEY "$(openssl rand -hex 16)"
resolve_cluster_setting "${SCRIPT_DIR}/.env" WAZUH_CLUSTER_NAME wazuh

echo "==> node/pkg:"
ls -lh "$PKG_DIR" | tail -n +2
