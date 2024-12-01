#!/bin/bash

MANAGER_URL="https://wazuh-manager:55000"
NGINX_URL="https://nginx-lb:55000"

echo "Waiting for the load balancer to be up..."

until ping -c1 nginx-lb > /dev/null 2>&1; do 
    sleep 1
done

echo "Waiting for the manager to be up..."

until curl -sfIo /dev/null "${MANAGER_URL}/"; do
    sleep 1
done

# Register agent
/usr/share/wazuh-agent/bin/wazuh-agent --register --url $NGINX_URL --user $USER --password $PASSWORD

# Run agent
/usr/share/wazuh-agent/bin/wazuh-agent
