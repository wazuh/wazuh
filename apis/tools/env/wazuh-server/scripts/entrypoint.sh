#!/usr/bin/env bash

shutdown() {
    echo "Container stopped, shutting down server..."
    /usr/share/wazuh-server/bin/wazuh-server stop
}

# Trap SIGTERM
trap 'shutdown' SIGTERM

cp /tmp/wazuh-server.yml /etc/wazuh-server/wazuh-server.yml

chown -R wazuh-server:wazuh-server /etc/wazuh-server/certs

# Add indexer username and password to the keystore
/usr/share/wazuh-server/bin/wazuh-keystore -k indexer-username -v admin
/usr/share/wazuh-server/bin/wazuh-keystore -k indexer-password -v admin

# Create default RBAC resources
/scripts/rbac-setup.sh

/usr/share/wazuh-server/bin/wazuh-server start &

wait $!
