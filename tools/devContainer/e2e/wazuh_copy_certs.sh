#!/bin/bash
set -euo pipefail

# Save current directory
OLD_DIR=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DEST_DIR="/var/wazuh-manager/etc/certs"
ORIG_DIR="${SCRIPT_DIR}/certs"
WAZUH_USER="wazuh-manager"
WAZUH_GROUP="wazuh-manager"

# Check if user/group exists
if ! id -u "${WAZUH_USER}" >/dev/null 2>&1; then
    echo "User ${WAZUH_USER} does not exist. Exiting."
    exit 1
fi

if ! getent group "${WAZUH_GROUP}" >/dev/null 2>&1; then
    echo "Group ${WAZUH_GROUP} does not exist. Exiting."
    exit 1
fi

# Move to the script directory
cd "${SCRIPT_DIR}"
# Trap to return to the original directory
trap 'cd "$OLD_DIR"' EXIT

# Create destination directory if it doesn't exist. Layout per the unified
# manager cert scheme (wazuh/wazuh#38278): the directory is root:wazuh-manager
# 1770 (sticky) so the daemons can self-generate their certs but cannot replace
# the externally provisioned indexer material.
if [ ! -d "${DEST_DIR}" ]; then
    mkdir -p "${DEST_DIR}"
    chown root:${WAZUH_GROUP} "${DEST_DIR}"
    chmod 1770 "${DEST_DIR}"
fi

echo "Copying certificates to ${DEST_DIR}..."

# Copy certificates
# Array of certificate files to copy
CERT_ORG_FILES=("wazuh-1-key.pem" "wazuh-1.pem" "root-ca.pem")
# The manager's indexer client cert is etc/certs/indexer-connector.* since
# wazuh/wazuh#38278; older packages expect manager.*. Use the names the
# installed configuration references.
if grep -q "indexer-connector.pem" /var/wazuh-manager/etc/wazuh-manager.conf 2>/dev/null; then
    CERT_DST_FILES=("indexer-connector-key.pem" "indexer-connector.pem" "root-ca.pem")
else
    CERT_DST_FILES=("manager-key.pem" "manager.pem" "root-ca.pem")
fi

for i in "${!CERT_ORG_FILES[@]}"; do
    cp "${ORIG_DIR}/${CERT_ORG_FILES[$i]}" "${DEST_DIR}/${CERT_DST_FILES[$i]}"
    # Externally provisioned material is root-owned, group-readable: the
    # privilege-dropped daemons read it but cannot overwrite it.
    chown root:${WAZUH_GROUP} ${DEST_DIR}/${CERT_DST_FILES[$i]}
    chmod 640 ${DEST_DIR}/${CERT_DST_FILES[$i]}
    echo "Copied and set permissions for ${CERT_DST_FILES[$i]}"
done

echo "Done copying certificates."

# The manager ships its agent listeners bound to loopback (same operation as
# open_manager_listeners in e2e/init.sh, which can only apply it when the
# manager is already installed). Containerised agents reach the devContainer
# host over the docker bridge, so open the <remote> listeners here, where the
# manager is guaranteed to be installed.
CONF="/var/wazuh-manager/etc/wazuh-manager.conf"
if [ -f "$CONF" ]; then
    sed -i "/<remote>/,/<\/remote>/ {
        s|<local_ip>127\.0\.0\.1</local_ip>|<local_ip>0.0.0.0</local_ip>|
        s|<bind_addr>127\.0\.0\.1</bind_addr>|<bind_addr>0.0.0.0</bind_addr>|
    }" "$CONF"
    chown root:${WAZUH_GROUP} "$CONF"
    chmod 660 "$CONF"
    echo "Opened manager remote listeners for containerised agents."
fi
