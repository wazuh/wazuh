#!/bin/bash
set -e

CERTS_DIR="/certificates"

echo "=== CERTIFICATE GENERATION START ==="

if [ -f "${CERTS_DIR}/root-ca.pem" ]; then
    echo "Certificates already exist in ${CERTS_DIR}. Cleaning up."
    rm /certificates/*
fi

cd /tmp
if [ ! -f ./config.yml ]; then
    echo "ERROR: config.yml not found in /tmp"
    exit 1
fi

./wazuh-certs-tool.sh -A

echo "Copying and renaming certificates to ${CERTS_DIR}..."
chmod 755 "${CERTS_DIR}"
chmod 644 wazuh-certificates/*
cp -r wazuh-certificates/* "${CERTS_DIR}/"
DASHBOARD_DIR="/export/dashboard"

echo "=== PREPARING DASHBOARD CERTIFICATES ==="

mkdir -p "${DASHBOARD_DIR}"

cp "wazuh-certificates/root-ca.pem" "${DASHBOARD_DIR}/"
cp "wazuh-certificates/wazuh.dashboard.pem" "${DASHBOARD_DIR}/"
cp "wazuh-certificates/wazuh.dashboard-key.pem" "${DASHBOARD_DIR}/"

echo "Setting dashboard-specific permissions..."
chmod 555 "${DASHBOARD_DIR}/wazuh.dashboard-key.pem"

echo "Certificates generated successfully."
