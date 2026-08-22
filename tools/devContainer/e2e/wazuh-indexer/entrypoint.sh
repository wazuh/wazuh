#!/bin/bash
set -e

# Wait for certificates to be mounted
echo "Checking for certificates..."

# Set correct ownership and permissions for certificates in /etc/wazuh-indexer/certs/
if [ -d "/etc/wazuh-indexer/certs" ]; then
    echo "Setting up certificate permissions..."
    cp /certs/node-1-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
    cp /certs/node-1.pem /etc/wazuh-indexer/certs/indexer.pem
    cp /certs/root-ca.pem /etc/wazuh-indexer/certs/root-ca.pem
    cp /certs/admin.pem /etc/wazuh-indexer/certs/admin.pem
    cp /certs/admin-key.pem /etc/wazuh-indexer/certs/admin-key.pem
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs/
    chmod 640 /etc/wazuh-indexer/certs/*
fi

# Start wazuh-indexer service
echo "Starting wazuh-indexer..."
service wazuh-indexer start

# Wait for service to be ready
echo "Waiting for wazuh-indexer to be ready..."
sleep 3

# Check if server is up 'service wazuh-indexer status'
service wazuh-indexer status

if [ $? -ne 0 ]; then
    echo "Wazuh-indexer service failed to start."
    service wazuh-indexer restart
    sleep 3
    service wazuh-indexer status
    if [ $? -ne 0 ]; then
        echo "Wazuh-indexer service failed to start after restart. Exiting."
        exit 1
    fi
fi


# Initialize security only if not already done
INIT_FLAG="/etc/wazuh-indexer-init/.security_initialized"
if [ ! -f "$INIT_FLAG" ]; then
    echo "Initializing indexer security for the first time..."
    sleep 20
    /usr/share/wazuh-indexer/bin/indexer-security-init.sh

    # Create flag to indicate security has been initialized
    mkdir -p /etc/wazuh-indexer-init
    touch "$INIT_FLAG"
    echo "Security initialization completed and flag created."
else
    echo "Security already initialized, skipping initialization."
fi




echo "Wazuh-indexer is ready!"


# Keep container running - if CMD was provided, execute it, otherwise keep alive
if [ "$#" -gt 0 ] && [ "$1" != "/bin/bash" ]; then
    exec "$@"
else
    tail -f /dev/null
fi
