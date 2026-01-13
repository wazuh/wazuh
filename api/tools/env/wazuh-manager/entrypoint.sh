#!/usr/bin/env bash

set -e

WAZUH_CERTS_DIR="/var/ossec/etc/certs"
ROLE="$3"
NODE_CERT="${WAZUH_CERTS_DIR}/${NODE_NAME}.pem"
NODE_CERT_KEY="${WAZUH_CERTS_DIR}/${NODE_NAME}-key.pem"
SERVER_CERT="${WAZUH_CERT_DIR}/server.pem"
SERVER_CERT_KEY="${WAZUH_CERT_DIR}/server-key.pem"

echo "Waiting for certificates..."
while [ ! -f "${WAZUH_CERTS_DIR}/root-ca.pem" ]; do
  sleep 2
done
echo "Certificates found."

# Set indexer credentials (default: admin/admin)
echo 'admin' | /var/ossec/bin/wazuh-keystore -f indexer -k username
echo 'admin' | /var/ossec/bin/wazuh-keystore -f indexer -k password

# Configure ossec.conf and api.yaml based on the Master role
if [ "$ROLE" == "master" ]; then
    python3 /scripts/xml_parser.py /var/ossec/etc/ossec.conf /scripts/master_ossec_conf.xml
    sed -i "s:# access:access:g" /var/ossec/api/configuration/api.yaml
    sed -i "s:#  max_request_per_minute\: 300:  max_request_per_minute\: 99999:g" /var/ossec/api/configuration/api.yaml
else
    python3 /scripts/xml_parser.py /var/ossec/etc/ossec.conf /scripts/worker_ossec_conf.xml
fi

sed -i "s:wazuh_db.debug=0:wazuh_db.debug=2:g" /var/ossec/etc/internal_options.conf
sed -i "s:authd.debug=0:authd.debug=2:g" /var/ossec/etc/internal_options.conf
sed -i "s:remoted.debug=0:remoted.debug=2:g" /var/ossec/etc/internal_options.conf

# Set proper permissions
chmod 500 /var/ossec/etc/certs
chmod 400 /var/ossec/etc/certs/*
chown -R wazuh:wazuh /var/ossec/etc/certs

echo "Starting Wazuh..."
/var/ossec/bin/wazuh-control start

# Keep the container running
while true; do
    sleep 10
done
