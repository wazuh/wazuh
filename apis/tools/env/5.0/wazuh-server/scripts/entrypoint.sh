#!/usr/bin/env bash

cp /tmp/wazuh-server.yml /etc/wazuh-server/wazuh-server.yml

# Set node's name
sed -i "s:name\: server_01:name\: $2:g" /etc/wazuh-server/wazuh-server.yml

if [ "$3" != "manager" ]
then
    # TODO: rename type name to 'manager' once we do the name migration
    sed -i "s:type\: master:type\: worker:g" /etc/wazuh-server/wazuh-server.yml
fi

/usr/share/wazuh-server/bin/wazuh-server start -r
