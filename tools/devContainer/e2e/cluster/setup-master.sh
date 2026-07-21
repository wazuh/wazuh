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
CLUSTER_NAME="${CLUSTER_NAME:-wazuh}"
MASTER_NODE_NAME="${MASTER_NODE_NAME:-master}"
ENV_FILE="${SCRIPT_DIR}/.env"

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (writes to $(dirname "$CONF")); use sudo." >&2; exit 1; }
test -f "$CONF" || { echo "ERROR: manager config not found at $CONF" >&2; exit 1; }

# Reuse the shared cluster key from .env, or generate and persist it.
if [[ -z "${CLUSTER_KEY:-}" ]]; then
  if [[ -f "$ENV_FILE" ]] && grep -q '^WAZUH_CLUSTER_KEY=' "$ENV_FILE"; then
    CLUSTER_KEY="$(grep '^WAZUH_CLUSTER_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
  else
    CLUSTER_KEY="$(openssl rand -hex 16)"
    printf 'WAZUH_CLUSTER_KEY=%s\n' "$CLUSTER_KEY" >> "$ENV_FILE"
  fi
fi

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
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>
EOF

# Keep the first backup pristine across re-runs.
[[ -f "${CONF}.bak" ]] || cp "$CONF" "${CONF}.bak"

# Replace an existing <cluster> block, or insert one before the closing root tag
# (the default config ships without <cluster>, so a plain replace would be a no-op).
if grep -q '<cluster>' "$CONF"; then
  awk -v block="$BLOCK" '
    /<cluster>/    { print block; skip=1; next }
    skip && /<\/cluster>/ { skip=0; next }
    skip           { next }
                   { print }
  ' "$CONF" > "${CONF}.new"
else
  awk -v block="$BLOCK" '
    /<\/wazuh_config>/ && !done { print block; done=1 }
    { print }
  ' "$CONF" > "${CONF}.new"
fi
cat "${CONF}.new" > "$CONF" && rm -f "${CONF}.new"

echo "==> Host manager configured as cluster master (backup: ${CONF}.bak)"
echo "==> Cluster key in ${ENV_FILE}"
echo "==> Restarting the manager..."
# Use systemd only when it is actually the init system; in a container the
# systemctl shim can exit 0 without restarting, which would leave the new
# cluster config unloaded, so fall back to wazuh-manager-control there.
if [[ -d /run/systemd/system ]]; then
  systemctl restart wazuh-manager
else
  "${BIN}/wazuh-manager-control" restart
fi
echo "==> Done. Bring up workers with docker compose (see README)."
