#!/usr/bin/env bash

sed -i "s:<address>.*</address>:<address>$1</address>:g" /var/ossec/etc/ossec.conf
sed -i "s:agent.debug=0:agent.debug=2:g" /var/ossec/etc/internal_options.conf

sleep 1

if [ $2  \< "4.2.0" ]; then
  /var/ossec/bin/ossec-control start
else
  /var/ossec/bin/wazuh-control start
fi

# Keep the container running
while true; do
    sleep 10
done
