#!/bin/bash

[ "$(/var/wazuh-manager/bin/wazuh-manager-control status | grep -E 'clusterd is running' | wc -l)" == 1 ] || exit 1
exit 0
