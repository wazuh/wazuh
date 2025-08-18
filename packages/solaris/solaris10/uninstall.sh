#!/bin/sh
# uninstall script for wazuh-agent
# Wazuh, Inc 2015

control_binary="wazuh-control"

if [ ! -f /var/ossec/bin/${control_binary} ]; then
  control_binary="ossec-control"
fi

## Stop and remove application
/var/ossec/bin/${control_binary} stop
rm -rf /var/ossec/

# remove launchdaemons
rm -f /etc/init.d/wazuh-agent
rm -rf /etc/rc2.d/S97wazuh-agent
rm -rf /etc/rc3.d/S97wazuh-agent

## Remove User and Groups
userdel wazuh 2> /dev/null
groupdel wazuh 2> /dev/null

exit 0
