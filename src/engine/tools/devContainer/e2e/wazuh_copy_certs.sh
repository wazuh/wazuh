#!/bin/bash
set -euo pipefail

# Save current directory
OLD_DIR=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DEST_DIR="/etc/wazuh-server/certs"
ORIG_DIR="${SCRIPT_DIR}/certs"

SERVER_CONFIG_YML="/etc/wazuh-server/wazuh-server.yml"

# Move to the script directory
cd "${SCRIPT_DIR}"
# Trap to return to the original directory
trap 'cd "$OLD_DIR"' EXIT

# Copy certificates
cp "${ORIG_DIR}/wazuh-manager-key.pem" "${DEST_DIR}/server-1-key.pem"
cp "${ORIG_DIR}/wazuh-manager.pem" "${DEST_DIR}/server-1.pem"
cp "${ORIG_DIR}/root-ca.pem" "${DEST_DIR}/root-ca.pem"

echo "Certificates copied to ${DEST_DIR}"

# Change permissions
chown wazuh-server:wazuh-server ${DEST_DIR}/server-1-key.pem
chown wazuh-server:wazuh-server ${DEST_DIR}/server-1.pem
chown wazuh-server:wazuh-server ${DEST_DIR}/root-ca.pem

echo "Owner changed for certificates"

# Append engine config if not exist
if ! grep -q "^engine:" "$SERVER_CONFIG_YML"; then
  echo "The 'engine' key does not exist in the YAML file. Appending it now."
    cat wazuh-server/wazuh-server-append.yml >> ${SERVER_CONFIG_YML}
else
    echo "The 'engine' key already exists in the YAML file. No changes made."
fi
