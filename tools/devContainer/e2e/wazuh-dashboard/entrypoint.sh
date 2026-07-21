#!/bin/bash
set -e

# Set correct ownership and permissions for certificates in /etc/wazuh-dashboard/certs/
echo "Setting up certificate permissions..."
mkdir -p /etc/wazuh-dashboard/certs
cp /certs/root-ca.pem /etc/wazuh-dashboard/certs/root-ca.pem
cp /certs/dashboard.pem /etc/wazuh-dashboard/certs/dashboard.pem
cp /certs/dashboard-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
chmod 640 /etc/wazuh-dashboard/certs/*
chmod 750 /etc/wazuh-dashboard/certs/

# Start wazuh-dashboard service
# sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards -c /etc/wazuh-dashboard/opensearch_dashboards.yml
echo "Starting wazuh-dashboard..."

sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards -c /etc/wazuh-dashboard/opensearch_dashboards.yml
