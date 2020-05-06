#!/usr/bin/env bash

if [ "$HOSTNAME" == "wazuh-master" ]; then
  sed -i "s|experimental_features: no|experimental_features: yes|g" /var/ossec/api/configuration/api.yaml
  /var/ossec/bin/wazuh-apid restart
fi
