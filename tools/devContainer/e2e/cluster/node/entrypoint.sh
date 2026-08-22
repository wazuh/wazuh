#!/usr/bin/env bash
set -euo pipefail

CONF=/var/wazuh-manager/etc/wazuh-manager.conf
CERT_SRC=/certs
CERT_DST=/var/wazuh-manager/etc/certs
BIN=/var/wazuh-manager/bin

NODE_TYPE="${NODE_TYPE:-worker}"
NODE_NAME="${NODE_NAME:-$(hostname)}"
CLUSTER_NAME="${CLUSTER_NAME:-wazuh}"
MASTER_ADDR="${MASTER_ADDR:-host.docker.internal}"
INDEXER_HOST="${INDEXER_HOST:-wazuh-indexer}"
INDEXER_PORT="${INDEXER_PORT:-9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASSWORD="${INDEXER_PASSWORD:-admin}"
: "${CLUSTER_KEY:?CLUSTER_KEY is required and must match the master}"

# Ensure the runtime user exists (needed for the source-mode snapshot, harmless
# for package installs).
getent group wazuh-manager >/dev/null 2>&1 || groupadd -r wazuh-manager
getent passwd wazuh-manager >/dev/null 2>&1 || useradd -r -g wazuh-manager -d /var/wazuh-manager -s /sbin/nologin wazuh-manager

# Indexer certificates from the mounted bundle. Layout per the unified manager
# cert scheme (wazuh/wazuh#38278): dir root:wazuh-manager 1770 (sticky), the
# externally provisioned indexer material root:wazuh-manager 0640. The indexer
# client cert is indexer-connector.* since that change; older manager artifacts
# still expect manager.*, so use the names the installed config references.
if grep -q "indexer-connector.pem" "$CONF" 2>/dev/null; then
  IDX_CERT="indexer-connector.pem"; IDX_KEY="indexer-connector-key.pem"
else
  IDX_CERT="manager.pem"; IDX_KEY="manager-key.pem"
fi
install -d -o root -g wazuh-manager -m 1770 "$CERT_DST"
install -o root -g wazuh-manager -m 640 "$CERT_SRC/root-ca.pem"     "$CERT_DST/root-ca.pem"
install -o root -g wazuh-manager -m 640 "$CERT_SRC/wazuh-1.pem"     "$CERT_DST/$IDX_CERT"
install -o root -g wazuh-manager -m 640 "$CERT_SRC/wazuh-1-key.pem" "$CERT_DST/$IDX_KEY"

# Indexer credentials live in the manager keystore, not in the config file.
"$BIN/wazuh-manager-keystore" -f indexer -k username -v "$INDEXER_USER"
printf '%s' "$INDEXER_PASSWORD" | "$BIN/wazuh-manager-keystore" -f indexer -k password

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
    <hidden>no</hidden>
    <disabled>no</disabled>
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

# Own everything written above (config, keystore) as the runtime user...
chown -R wazuh-manager:wazuh-manager /var/wazuh-manager
# ...except the externally provisioned certs, which stay root-owned (see above).
chown root:wazuh-manager "$CERT_DST" "$CERT_DST"/*
chmod 1770 "$CERT_DST"

"$BIN/wazuh-manager-control" start || true

touch /var/wazuh-manager/logs/wazuh-manager.log
exec tail -f /var/wazuh-manager/logs/wazuh-manager.log
