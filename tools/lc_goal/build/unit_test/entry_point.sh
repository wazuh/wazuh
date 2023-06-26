#!/bin/bash

service wazuh-manager start &
sleep 5 && service wazuh-indexer start &
service filebeat start &
sleep 5 && /etc/systemd/system/wazuh-dashboard start &
sleep 15 && /usr/share/wazuh-indexer/bin/indexer-security-init.sh &

sleep infinity




