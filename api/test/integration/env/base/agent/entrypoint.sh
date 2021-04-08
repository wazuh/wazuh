#!/usr/bin/env bash

# Apply test.keys
cp /tmp/configuration_files/test.keys /var/ossec/etc/test.keys

# Remove agent_4.x in agents with version 3.x
if [ "$3" == "agent_old" ]; then
  rm /tmp/configuration_files/agent_4.x.conf
fi

# Modify agent.conf
for conf_file in /tmp/configuration_files/*.conf; do
  python3 /tools/xml_parser.py /var/ossec/etc/agent.conf $conf_file
done

sed -n "/$2 /p" /var/ossec/etc/test.keys > /var/ossec/etc/client.keys
chown root:ossec /var/ossec/etc/client.keys
rm /var/ossec/etc/test.keys

# Agent configuration
for sh_file in /tmp/configuration_files/*.sh; do
  . $sh_file
done

/var/ossec/bin/wazuh-control start || /var/ossec/bin/ossec-control start

tail -f /var/ossec/logs/ossec.log
