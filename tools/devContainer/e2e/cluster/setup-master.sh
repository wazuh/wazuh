#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Turn the manager running on the host into the cluster master. No load balancer
# is used: workers join this master directly and agents are pointed at a node by
# hand. Run on the host before bringing up the workers.
# ------------------------------------------------------------------------------
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

CONF="${WAZUH_MANAGER_CONF:-/var/wazuh-manager/etc/wazuh-manager.conf}"
BIN="$(dirname "$CONF")/../bin"
MASTER_NODE_NAME="${MASTER_NODE_NAME:-master}"
ENV_FILE="${SCRIPT_DIR}/.env"

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (writes to $(dirname "$CONF")); use sudo." >&2; exit 1; }
test -f "$CONF" || { echo "ERROR: manager config not found at $CONF" >&2; exit 1; }

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
resolve_cluster_setting "$ENV_FILE" WAZUH_CLUSTER_KEY "$(openssl rand -hex 16)"; CLUSTER_KEY="$REPLY"
resolve_cluster_setting "$ENV_FILE" WAZUH_CLUSTER_NAME wazuh; CLUSTER_NAME="$REPLY"

read -r -d '' BLOCK <<EOF || true
  <cluster>
    <name>${CLUSTER_NAME}</name>
    <node_name>${MASTER_NODE_NAME}</node_name>
    <node_type>master</node_type>
    <key>${CLUSTER_KEY}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>127.0.0.1</node>
    </nodes>
  </cluster>
EOF

# Keep the first backup pristine across re-runs.
[[ -f "${CONF}.bak" ]] || cp "$CONF" "${CONF}.bak"

# Replace an existing <cluster> block, or insert one before the closing root tag
# (the default config ships without <cluster>, so a plain replace would be a no-op).
if grep -q '<cluster>' "$CONF"; then
  # Only the first block is replaced, and a block opened and closed on the same
  # line must not switch skipping on (it would drop the rest of the file).
  awk -v block="$BLOCK" '
    /<cluster>/ && !done { print block; done=1; if ($0 !~ /<\/cluster>/) skip=1; next }
    skip && /<\/cluster>/ { skip=0; next }
    skip                 { next }
                         { print }
  ' "$CONF" > "${CONF}.new"
else
  awk -v block="$BLOCK" '
    /<\/wazuh_config>/ && !done { print block; done=1 }
    { print }
  ' "$CONF" > "${CONF}.new"
fi
# Validate the staged file (XML, schema, cross-field rules) before it replaces
# the configuration; an invalid result leaves the original untouched.
if ! "${BIN}/wazuh-manager-conf" -f "${CONF}.new" validate; then
  echo "ERROR: the new cluster configuration does not validate; ${CONF} left unchanged." >&2
  rm -f "${CONF}.new"
  exit 1
fi
cat "${CONF}.new" > "$CONF" && rm -f "${CONF}.new"

echo "==> Host manager configured as cluster master (backup: ${CONF}.bak)"
echo "==> Cluster key in ${ENV_FILE}"
echo "==> Restarting the manager..."
# Use systemd only when it is actually the init system (PID 1). /run/systemd/system
# alone proves nothing: it also exists in the devcontainer, where the manager
# installer creates it and there is no systemd bus (see .devcontainer/fix-dind.sh),
# and in a container the systemctl shim can exit 0 without restarting. Either way
# the new cluster config would stay unloaded, so check that clusterd came up.
if [[ "$(cat /proc/1/comm 2>/dev/null)" == systemd ]]; then
  systemctl restart wazuh-manager
else
  "${BIN}/wazuh-manager-control" restart
fi
# status exits 1 when any daemon is down: read its output apart from its exit code.
STATUS="$("${BIN}/wazuh-manager-control" status)" || true
if ! grep -q '^wazuh-manager-clusterd is running' <<<"$STATUS"; then
  echo "ERROR: wazuh-manager-clusterd is not running after the restart; see $(dirname "$CONF")/../logs/wazuh-manager.log" >&2
  echo "       The previous config is in ${CONF}.bak." >&2
  exit 1
fi
echo "==> Done. Bring up workers with docker compose (see README)."
