#!/usr/bin/env bash

# Set right permissions for test_config data
chown root:ossec /var/ossec/etc/ossec.conf
chown root:ossec /var/ossec/etc/client.keys
chown -R ossec:ossec /var/ossec/queue/agent-groups
chown -R ossecr:ossec /var/ossec/var/multigroups
chown -R ossec:ossec /var/ossec/etc/shared
chown root:ossec /var/ossec/etc/shared/ar.conf
chown -R ossecr:ossec /var/ossec/queue/agent-info

sleep 1

/var/ossec/bin/ossec-control start

/usr/bin/supervisord
