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

# Issue the Server API (apid) pair, signed by the root CA the tool just created: the API no longer
# generates its own certificate. Same profile as the installer's.
echo "Issuing the Server API certificate..."
CA_DIR=wazuh-certificates
OUT=wazuh-certificates
printf '%s\n' \
  'basicConstraints = critical,CA:FALSE' \
  'keyUsage = critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage = serverAuth' \
  'subjectAltName = DNS:localhost' \
  'subjectKeyIdentifier = hash' \
  'authorityKeyIdentifier = keyid,issuer' > "$OUT/apid.ext"
(umask 077; openssl req -new -nodes -newkey rsa:2048 -sha256 \
  -subj '/C=US/ST=California/L=San Francisco/O=Wazuh/CN=wazuh.com' \
  -keyout "$OUT/apid-key.pem" -out "$OUT/apid.csr")
openssl x509 -req -sha256 -days 3650 -set_serial "0x$(openssl rand -hex 16)" \
  -in "$OUT/apid.csr" -CA "$CA_DIR/root-ca.pem" -CAkey "$CA_DIR/root-ca.key" \
  -extfile "$OUT/apid.ext" -out "$OUT/apid.pem"
rm -f "$OUT/apid.csr" "$OUT/apid.ext"
openssl verify -purpose sslserver -verify_hostname localhost -CAfile "$CA_DIR/root-ca.pem" "$OUT/apid.pem"

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
