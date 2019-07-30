#!/usr/bin/env bash

/var/ossec/bin/ossec-control stop

sed -i "s:MANAGER_IP:$1:g" /var/ossec/etc/ossec.conf
sed -i "s:<protocol>udp</protocol>:<protocol>tcp</protocol>:g" /var/ossec/etc/ossec.conf
sed -n "/$2 /p" /var/ossec/etc/test.keys > /var/ossec/etc/client.keys
chown root:ossec /var/ossec/etc/client.keys
rm -rf /var/ossec/etc/test.keys

sleep 1

/var/ossec/bin/ossec-control start

tail -f /var/ossec/logs/ossec.log
