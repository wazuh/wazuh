#!/bin/sh
# uninstall script for wazuh-agent
# Wazuh, Inc 2015

install_path=$1
control_binary=$2

## Stop and remove application
${install_path}/bin/${control_binary} stop
rm -r /var/ossec*

# remove launchdaemons
rm -f /etc/init.d/wazuh-agent

## Remove User and Groups
userdel wazuh
groupdel wazuh

exit 0
