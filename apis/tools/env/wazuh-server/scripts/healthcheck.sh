#!/bin/bash

[ "$(/usr/share/wazuh-server/bin/wazuh-server status | grep -E 'wazuh-server is running' | wc -l)" == 1 ] || exit 1
exit 0
