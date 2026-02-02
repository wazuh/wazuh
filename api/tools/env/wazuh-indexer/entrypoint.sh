#!/bin/bash
set -e

CERTS_DIR="/var/ossec/etc/certs"
NODE_CERT="${CERTS_DIR}/node-1.pem"
INDEXER_CERT="${CERTS_DIR}/indexer.pem"
NODE_CERT_KEY="${CERTS_DIR}/node-1-key.pem"
INDEXER_CERT_KEY="${CERTS_DIR}/indexer-key.pem"

echo "Waiting for certificates..."
while [ ! -f "${CERTS_DIR}/root-ca.pem" ]; do
  sleep 2
done

echo "Certificates found."

cp /var/ossec/etc/certs/* /etc/wazuh-indexer/certs


if [[ -f "$INDEXER_CERT" ]]; then
    echo "Indexer certificate already correctly named. Nothing to do."

elif [[ -f "$NODE_CERT" ]]; then
    echo "Renaming node-1.pem to indexer.pem"
    mv "$NODE_CERT" "$INDEXER_CERT" || {
        echo "ERROR: Failed to rename node-1.pem to indexer.pem"
        exit 1
    }

else
    echo "ERROR: Neither node-1.pem nor indexer.pem found in $CERTS_DIR"
    exit 1
fi

if [[ -f "$INDEXER_CERT_KEY" ]]; then
    echo "Indexer certificate already correctly named. Nothing to do."

elif [[ -f "$NODE_CERT_KEY" ]]; then
    echo "Renaming node-1.pem to indexer.pem"
    mv "$NODE_CERT_KEY" "$INDEXER_CERT_KEY" || {
        echo "ERROR: Failed to rename node-1.pem to indexer.pem"
        exit 1
    }

else
    echo "ERROR: Neither node-1.pem nor indexer.pem found in $CERTS_DIR"
    exit 1
fi

chmod 500 /etc/wazuh-indexer/certs

chmod 400 /etc/wazuh-indexer/certs/*

chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

# Start wazuh-indexer service
echo "Starting wazuh-indexer..."
service wazuh-indexer start

# Wait for wazuh-indexer API to be available (Health Check Loop)
echo "Waiting for wazuh-indexer API to be available on port 9200..."
MAX_RETRIES=30
RETRY_COUNT=0

until curl -s -k https://localhost:9200 > /dev/null; do
    RETRY_COUNT=$((RETRY_COUNT+1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "ERROR: Wazuh-indexer API failed to respond after $MAX_RETRIES attempts."
        exit 1
    fi
    echo "Indexer is still starting... (Attempt $RETRY_COUNT/$MAX_RETRIES)"
    sleep 5
done

# Check if server is up 'service wazuh-indexer status'
service wazuh-indexer status

if [ $? -ne 0 ]; then
    echo "Wazuh-indexer service failed to start."
    service wazuh-indexer restart
    sleep 10
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
