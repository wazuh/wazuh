#!/bin/sh
# postremove script for wazuh-agent
# Wazuh, Inc 2015

if getent passwd wazuh > /dev/null 2>&1; then
  userdel wazuh
fi

if getent group wazuh > /dev/null 2>&1; then
  groupdel wazuh
fi

# pkgrm only removes the pathnames listed in the package, so files created at
# runtime and the directories holding them are left behind
rm -rf /var/ossec
