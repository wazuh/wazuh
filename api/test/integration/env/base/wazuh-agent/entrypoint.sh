#!/usr/bin/env bash

/var/ossec/bin/ossec-control stop

sed -i "s:MANAGER_IP:$1:g" /var/ossec/etc/ossec.conf
sed -i "s:<protocol>udp</protocol>:<protocol>tcp</protocol>:g" /var/ossec/etc/ossec.conf
sed -n "/$2 /p" /var/ossec/etc/test.keys > /var/ossec/etc/client.keys
chown root:ossec /var/ossec/etc/client.keys
rm /var/ossec/etc/test.keys

## Disable active-response for agent 003
#if [ "X$2" == "Xwazuh-agent3" ]; then
#      sed -i "/<active-response>/{n;s/no/yes/}" /var/ossec/etc/ossec.conf
#fi

sleep 1

/var/ossec/bin/ossec-control start

tail -f /var/ossec/logs/ossec.log
