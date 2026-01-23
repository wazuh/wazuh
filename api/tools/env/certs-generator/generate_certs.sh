#!/bin/bash
set -e

CERTS_DIR="/certificates"

echo "=== CERTIFICATE GENERATION START ==="

if [ -f "${CERTS_DIR}/root-ca.pem" ]; then
    echo "Certificates already exist in ${CERTS_DIR}. Skipping generation."
    exit 0
fi

cd /tmp
if [ ! -f ./config.yml ]; then
    echo "ERROR: config.yml not found in /tmp"
    exit 1
fi

./wazuh-certs-tool.sh -A

echo "Copying and renaming certificates to ${CERTS_DIR}..."
cp -r wazuh-certificates/* "${CERTS_DIR}/"

echo "Certificates generated successfully."
