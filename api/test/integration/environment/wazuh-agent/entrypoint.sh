#!/usr/bin/env bash

until /var/ossec/bin/agent-auth -m $1; do
  echo "Wazuh manager is unavailable - sleeping for 5 seconds"
  sleep 5
done

sed -i "s:MANAGER_IP:$2:g" /var/ossec/etc/ossec.conf

sleep 5

/var/ossec/bin/ossec-control stop
/var/ossec/bin/ossec-control start
tail -f /var/ossec/logs/ossec.log
