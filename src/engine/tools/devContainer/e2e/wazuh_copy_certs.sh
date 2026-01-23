#!/bin/bash
set -euo pipefail

# Save current directory
OLD_DIR=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DEST_DIR="/var/ossec/etc/certs"
ORIG_DIR="${SCRIPT_DIR}/certs"
WAZUH_USER="wazuh"
WAZUH_GROUP="wazuh"

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

# Create destination directory if it doesn't exist
if [ ! -d "${DEST_DIR}" ]; then
    mkdir -p "${DEST_DIR}"
    chown ${WAZUH_USER}:${WAZUH_GROUP} "${DEST_DIR}"
    chmod 750 "${DEST_DIR}"
fi

echo "Copying certificates to ${DEST_DIR}..."

# Copy certificates
# Array of certificate files to copy
CERT_ORG_FILES=("wazuh-1-key.pem" "wazuh-1.pem" "root-ca.pem")
CERT_DST_FILES=("server-key.pem" "server.pem" "root-ca.pem")

for i in "${!CERT_ORG_FILES[@]}"; do
    cp "${ORIG_DIR}/${CERT_ORG_FILES[$i]}" "${DEST_DIR}/${CERT_DST_FILES[$i]}"
    chown ${WAZUH_USER}:${WAZUH_GROUP} ${DEST_DIR}/${CERT_DST_FILES[$i]}
    chmod 640 ${DEST_DIR}/${CERT_DST_FILES[$i]}
    echo "Copied and set permissions for ${CERT_DST_FILES[$i]}"
done

echo "Done copying certificates."
