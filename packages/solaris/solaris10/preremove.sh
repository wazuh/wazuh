#!/bin/sh
# preremove script for wazuh-agent
# Wazuh, Inc 2015

control_binary="wazuh-control"

if [ ! -f /var/ossec/bin/${control_binary} ]; then
  control_binary="ossec-control"
fi

/var/ossec/bin/${control_binary} stop
