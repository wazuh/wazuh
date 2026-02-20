#!/usr/bin/env bash

set -e

WAZUH_CERTS_DIR="/var/wazuh-manager/etc/certs"
ROLE="$3"
NODE_CERT="${WAZUH_CERTS_DIR}/${NODE_NAME}.pem"
NODE_CERT_KEY="${WAZUH_CERTS_DIR}/${NODE_NAME}-key.pem"
SERVER_CERT="${WAZUH_CERT_DIR}/manager.pem"
SERVER_CERT_KEY="${WAZUH_CERT_DIR}/manager-key.pem"

echo "Waiting for certificates..."
while [ ! -f "${WAZUH_CERTS_DIR}/root-ca.pem" ]; do
  sleep 2
done
echo "Certificates found."

# Set indexer credentials (default: admin/admin)
echo 'admin' | /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username
echo 'admin' | /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password

# Configure wazuh configuration file and api.yaml based on the Master role
if [ "$ROLE" == "master" ]; then
    python3 /scripts/xml_parser.py /var/wazuh-manager/etc/wazuh-manager.conf /scripts/master_wazuh-manager_conf.xml
    sed -i "s:# access:access:g" /var/wazuh-manager/api/configuration/api.yaml
    sed -i "s:#  max_request_per_minute\: 300:  max_request_per_minute\: 99999:g" /var/wazuh-manager/api/configuration/api.yaml
else
    python3 /scripts/xml_parser.py /var/wazuh-manager/etc/wazuh-manager.conf /scripts/worker_wazuh-manager_conf.xml
fi

sed -i "s:wazuh_db.debug=0:wazuh_db.debug=2:g" /var/wazuh-manager/etc/internal_options.conf
sed -i "s:authd.debug=0:authd.debug=2:g" /var/wazuh-manager/etc/internal_options.conf
sed -i "s:remoted.debug=0:remoted.debug=2:g" /var/wazuh-manager/etc/internal_options.conf

# Set proper permissions
chmod 500 /var/wazuh-manager/etc/certs
chmod 400 /var/wazuh-manager/etc/certs/*
chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/etc/certs

echo "Starting Wazuh..."
/var/wazuh-manager/bin/wazuh-manager-control start

# Keep the container running
while true; do
    sleep 10
done
