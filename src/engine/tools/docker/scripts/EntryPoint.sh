#!/usr/bin/env bash

/usr/sbin/sshd
WAZUH_CONFIG_SKIP_API=true /usr/share/wazuh-server/bin/wazuh-engine
