#!/bin/bash
set -e

CERTS_DIR="/var/ossec/etc/certs"

echo "=== CERTIFICATE GENERATION START ==="

if [ -f "${CERTS_DIR}/root-ca.pem" ]; then
    echo "Certificates already exist. Skipping generation."
    exit 0
fi

if [ ! -f /tmp/config.yml ]; then
    echo "ERROR: config.yml not found"
    exit 1
fi

mkdir -p "${CERTS_DIR}"

cd /tmp
./wazuh-certs-tool.sh -A

echo "Copying certificates..."
cp -r wazuh-certificates/* "${CERTS_DIR}/"

mv ${CERTS_DIR}/wazuh-master.pem ${CERTS_DIR}/server.pem
mv ${CERTS_DIR}/wazuh-master-key.pem ${CERTS_DIR}/server-key.pem

echo "Certificates generated successfully."
