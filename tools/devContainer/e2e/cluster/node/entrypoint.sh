#!/usr/bin/env bash
set -euo pipefail

CONF=/var/wazuh-manager/etc/wazuh-manager.conf
CERT_SRC=/certs
CERT_DST=/var/wazuh-manager/etc/certs
BIN=/var/wazuh-manager/bin

# The manager binaries resolve paths such as queue/keystore relative to the
# working directory, not to an environment variable.
cd /var/wazuh-manager

NODE_TYPE="${NODE_TYPE:-worker}"
NODE_NAME="${NODE_NAME:-$(hostname)}"
CLUSTER_NAME="${CLUSTER_NAME:-wazuh}"
MASTER_ADDR="${MASTER_ADDR:-host.docker.internal}"
INDEXER_HOST="${INDEXER_HOST:-wazuh-indexer}"
INDEXER_PORT="${INDEXER_PORT:-9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASSWORD="${INDEXER_PASSWORD:-admin}"
: "${CLUSTER_KEY:?CLUSTER_KEY is required and must match the master}"

# The runtime user comes from the package or, in source mode, from the image
# build, which creates it with the host's numeric ids before extracting the tree
# (node/Dockerfile). Nothing here changes the ownership of the installation: the
# tree root, bin/ and lib/ stay root-owned and bin/wazuh-manager-service-control
# keeps its setuid bit, both of which that helper checks before it acts
# (src/util/manager_service_control/main.c); a chown would clear the bit.
getent passwd wazuh-manager >/dev/null 2>&1 || { echo "ERROR: the image has no wazuh-manager user" >&2; exit 1; }

# Source mode ships the tree without logs/, queue/ and var/ (the master's live
# state, excluded by cluster/init.sh). The daemons do not create these
# directories themselves, so recreate the fixed skeleton with the owners and
# modes of an installed manager (dynamic entries such as queue/cluster/<node> are
# the daemons' own). Directories that exist (package install) are left alone.
skel() {  # skel <mode> <owner:group> <dir>...
  local mode=$1 owner=$2 d; shift 2
  for d in "$@"; do [[ -d $d ]] || install -d -o "${owner%:*}" -g "${owner#*:}" -m "$mode" "$d"; done
}
skel 770 wazuh-manager:wazuh-manager logs queue
skel 750 wazuh-manager:wazuh-manager logs/api logs/cluster logs/wazuh queue/authd queue/db queue/keystore
skel 770 wazuh-manager:wazuh-manager queue/cluster queue/indexer queue/rids queue/sockets queue/tasks queue/vd
skel 750 root:wazuh-manager var
skel 770 root:wazuh-manager var/db var/download var/run var/upgrade
skel 770 wazuh-manager:wazuh-manager var/multigroups

# Certificates from the mounted bundle, issued by e2e/init.sh with the unified
# manager layout (wazuh/wazuh#38278): dir root:wazuh-manager 1770 (sticky); the
# externally provisioned indexer material root:wazuh-manager 0640; the agent
# listener pair wazuh-manager-owned, since remoted opens it after dropping
# privileges. The installer no longer generates remoted.pem, so the worker deploys
# the manager node's <name>-remoted leaf, as wazuh_copy_certs.sh does on the host.
NODE_CERT="${MANAGER_NODE_NAME:-wazuh-1}"
install -d -o root -g wazuh-manager -m 1770 "$CERT_DST"
install -o root -g wazuh-manager -m 640 "$CERT_SRC/root-ca.pem"                  "$CERT_DST/root-ca.pem"
install -o root -g wazuh-manager -m 640 "$CERT_SRC/${NODE_CERT}.pem"             "$CERT_DST/indexer-connector.pem"
install -o root -g wazuh-manager -m 640 "$CERT_SRC/${NODE_CERT}-key.pem"         "$CERT_DST/indexer-connector-key.pem"
install -o wazuh-manager -g wazuh-manager -m 640 "$CERT_SRC/${NODE_CERT}-remoted.pem"     "$CERT_DST/remoted.pem"
install -o wazuh-manager -g wazuh-manager -m 640 "$CERT_SRC/${NODE_CERT}-remoted-key.pem" "$CERT_DST/remoted-key.pem"

# Indexer credentials live in the manager keystore, not in the config file.
"$BIN/wazuh-manager-keystore" -f indexer -k username -v "$INDEXER_USER"
printf '%s' "$INDEXER_PASSWORD" | "$BIN/wazuh-manager-keystore" -f indexer -k password
# The keystore tool runs as root here: hand what it wrote back to the runtime
# user, as on an installed manager.
chown -R wazuh-manager:wazuh-manager queue/keystore

# Point the indexer connection at the indexer container.
sed -i "s#<host>https://[^<]*</host>#<host>https://${INDEXER_HOST}:${INDEXER_PORT}</host>#" "$CONF"

# Replace the <cluster> block with this node's definition (workers join the
# master that runs on the host; no load balancer is involved).
read -r -d '' BLOCK <<EOF || true
  <cluster>
    <name>${CLUSTER_NAME}</name>
    <node_name>${NODE_NAME}</node_name>
    <node_type>${NODE_TYPE}</node_type>
    <key>${CLUSTER_KEY}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>${MASTER_ADDR}</node>
    </nodes>
  </cluster>
EOF

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

# A worker that cannot start must not look alive: exit, so Docker shows the
# container as exited (healthcheck.sh covers a daemon that dies later).
if ! "$BIN/wazuh-manager-control" start; then
  echo "ERROR: wazuh-manager failed to start on ${NODE_NAME}; last lines of wazuh-manager.log:" >&2
  tail -n 40 /var/wazuh-manager/logs/wazuh-manager.log >&2 || true
  exit 1
fi

touch /var/wazuh-manager/logs/wazuh-manager.log
exec tail -f /var/wazuh-manager/logs/wazuh-manager.log
