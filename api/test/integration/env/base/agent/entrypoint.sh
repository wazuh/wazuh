#!/usr/bin/env bash

sed -i "s:MANAGER_IP:$1:g" /var/ossec/etc/ossec.conf
sed -i "s:<protocol>udp</protocol>:<protocol>tcp</protocol>:g" /var/ossec/etc/ossec.conf
sed -n "/$2 /p" /var/ossec/etc/test.keys > /var/ossec/etc/client.keys
chown root:ossec /var/ossec/etc/client.keys
rm /var/ossec/etc/test.keys

# Agent configuration
for sh_file in /configuration_files/*.sh; do
  . $sh_file
done

sleep 1

/var/ossec/bin/ossec-control start

tail -f /var/ossec/logs/ossec.log
