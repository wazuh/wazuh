#!/bin/bash

MANAGER_URL="https://wazuh-manager:55000"
NGINX_URL="https://nginx-lb:55000"

echo "Waiting for the load balancer to be up..."

until ping -c1 nginx-lb > /dev/null 2>&1; do 
    sleep 1
done

echo "Waiting for the manager to be up..."

while true
do
    curl -ksfIo /dev/null "${MANAGER_URL}/"
    if [[ "$?" -eq 22 ]]; then
        break
    fi
    sleep 1
done

# Wait some time for the nodes to sync the JWT key pair and configurations
echo "Waiting for the nodes to sync..."
sleep 10

# Register agent
SPDLOG_LEVEL=TRACE /usr/share/wazuh-agent/bin/wazuh-agent --register --url $NGINX_URL --user $USER --password $PASSWORD

# Run agent
SPDLOG_LEVEL=TRACE /usr/share/wazuh-agent/bin/wazuh-agent
