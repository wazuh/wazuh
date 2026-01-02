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

cp wazuh-certificates/wazuh-master-key.pem wazuh-certificates/server-key.pem
cp wazuh-certificates/wazuh-master.pem wazuh-certificates/server.pem

echo "Copying certificates..."
cp -r wazuh-certificates/* "${CERTS_DIR}/"

chmod 600 "${CERTS_DIR}"/*
echo "Certificates generated successfully."


