#!/bin/bash

# Save current directory
OLD_DIR=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DEST_DIR="/etc/wazuh-server/certs"
ORIG_DIR="${SCRIPT_DIR}/certs"

# Move to the script directory
cd "${SCRIPT_DIR}"
# Trap to return to the original directory
trap 'cd "$OLD_DIR"' EXIT

# Copy certificates
cp "${ORIG_DIR}/wazuh-manager-key.pem" "${DEST_DIR}/server-1-key.pem"
cp "${ORIG_DIR}/wazuh-manager.pem" "${DEST_DIR}/server-1.pem"
cp "${ORIG_DIR}/root-ca.pem" "${DEST_DIR}/root-ca.pem"

# Change permissions
chown wazuh-server:wazuh-server ${DEST_DIR}/server-1-key.pem
chown wazuh-server:wazuh-server ${DEST_DIR}/server-1.pem
chown wazuh-server:wazuh-server ${DEST_DIR}/root-ca.pem

# Append engine config
cat wazuh-server/wazuh-server-append.yml >> /etc/wazuh-server/wazuh-server.yml
