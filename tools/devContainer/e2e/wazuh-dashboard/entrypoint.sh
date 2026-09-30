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

# ----------------------------------------------------------------------------
# Resolve the consumed passwords with the package's resolver.
#
# The container env (env_file .credentials.env) carries
# WAZUH_INDEXER_KIBANASERVER_PASSWORD and WAZUH_MANAGER_WUI_PASSWORD; the
# resolver stores them in the keystore (opensearch.username/opensearch.password
# and wazuh_core.hosts.default.password), never in opensearch_dashboards.yml.
# Tolerated failure: without the env it exits non-zero (it owns no password),
# and set -e would restart the container in a loop. Degraded, not demo: the
# dashboard starts and its indexer/manager connections stay unauthenticated
# until the env is fixed and the container recreated.
# ----------------------------------------------------------------------------
/usr/share/wazuh-dashboard/bin/resolve-credentials --prestart || echo "WARN: credentials resolution failed (degraded)"

# Start wazuh-dashboard service
echo "Starting wazuh-dashboard..."

sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards -c /etc/wazuh-dashboard/opensearch_dashboards.yml
