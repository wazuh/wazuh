#!/bin/bash

service wazuh-manager start &
sleep 15 && service wazuh-indexer start &
service filebeat start &
/etc/systemd/system/wazuh-dashboard start &
sleep 40 && /usr/share/wazuh-indexer/bin/indexer-security-init.sh &

sleep infinity




