#!/usr/bin/env bash

sleep 5

sed -i "s:MANAGER_IP:$1:g" /var/ossec/etc/ossec.conf
sed -i "s:<protocol>udp</protocol>:<protocol>tcp</protocol>:g" /var/ossec/etc/ossec.conf

until /var/ossec/bin/agent-auth -m $1; do
  echo "Wazuh manager is unavailable - sleeping for 5 seconds"
  sleep 5
done

sleep 5

/var/ossec/bin/ossec-control stop
/var/ossec/bin/ossec-control start
tail -f /var/ossec/logs/ossec.log
