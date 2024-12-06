#!/usr/bin/env bash

# Enable debug mode for the modulesd daemon
echo 'wazuh_modules.debug=2' >> /var/ossec/etc/local_internal_options.conf

# Apply test.keys
cp /tmp_volume/configuration_files/test.keys /var/ossec/etc/test.keys

# Modify ossec.conf
for conf_file in /tmp_volume/configuration_files/*.conf; do
  # Do not apply 4.x configuration changes to agents with version 3.x
  if [ "$3" == "agent_old" ] && [ $conf_file == "/tmp_volume/configuration_files/ossec_4.x.conf" ]; then
    continue
  fi

  python3 /tools/xml_parser.py /var/ossec/etc/ossec.conf $conf_file
done

sed -n "/$2 /p" /var/ossec/etc/test.keys > /var/ossec/etc/client.keys
chown root:wazuh /var/ossec/etc/client.keys
rm /var/ossec/etc/test.keys

# Agent configuration
for sh_file in /tmp_volume/configuration_files/*.sh; do
  . $sh_file
done

/var/ossec/bin/wazuh-control start || /var/ossec/bin/ossec-control start

tail -f /var/ossec/logs/ossec.log
