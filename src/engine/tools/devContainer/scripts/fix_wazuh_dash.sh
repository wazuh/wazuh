#!/bin/bash

CERT_ORG="/workspaces/wazuh-5.x/scripts_public/certs"

# Check if wazuh-dashboard user exists
if ! id -u wazuh-dashboard >/dev/null 2>&1; then
    echo "User 'wazuh-dashboard' does not exist. Please install wazuh-dashboard before running this script."
    exit 1
fi

# Copy certificates to wazuh-dashboard certs folder

mkdir /etc/wazuh-dashboard/certs/                                                                                                                         2 ↵
cp ${CERT_ORG}/dashboard-key.pem /etc/wazuh-dashboard/certs/
cp ${CERT_ORG}/dashboard.pem /etc/wazuh-dashboard/certs/
cp ${CERT_ORG}/root-ca.pem /etc/wazuh-dashboard/certs/
chmod 750  /etc/wazuh-dashboard/certs/
chmod 640  /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard  /etc/wazuh-dashboard/certs


# /usr/share/wazuh-dashboard/bin/opensearch-dashboards -c /etc/wazuh-dashboard/opensearch_dashboards.yml --allow-root
cp -a /etc/wazuh-dashboard/opensearch_dashboards.yml /etc/wazuh-dashboard/opensearch_dashboards_custom.yml

# Replace localhost with 127.0.0.1
sed -i 's/localhost/127.0.0.1/g' /etc/wazuh-dashboard/opensearch_dashboards_custom.yml

# Restart wazuh-dashboard service
echo "Run: "
echo 'sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards -c /etc/wazuh-dashboard/custom_opensearch_dashboards.yml'
