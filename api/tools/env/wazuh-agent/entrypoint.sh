#!/usr/bin/env bash

sed -i "s:<endpoint>.*</endpoint>:<endpoint>$1</endpoint>:g" /var/ossec/etc/ossec.conf
sed -i "s:agent.debug=0:agent.debug=2:g" /var/ossec/etc/internal_options.conf

sleep 1

/var/ossec/bin/wazuh-control start

# Keep the container running
while true; do
    sleep 10
done
