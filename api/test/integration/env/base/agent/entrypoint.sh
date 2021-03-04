#!/usr/bin/env bash

# Modify ossec.conf
for conf_file in /configuration_files/*.conf; do
  python3 /tools/xml_parser.py /var/ossec/etc/ossec.conf $conf_file
done

sed -n "/$2 /p" /var/ossec/etc/test.keys > /var/ossec/etc/client.keys
chown root:ossec /var/ossec/etc/client.keys
rm /var/ossec/etc/test.keys

# Agent configuration
for sh_file in /configuration_files/*.sh; do
  . $sh_file
done

/var/ossec/bin/wazuh-control start || /var/ossec/bin/ossec-control start

tail -f /var/ossec/logs/ossec.log
