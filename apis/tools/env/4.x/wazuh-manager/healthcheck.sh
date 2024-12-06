#!/bin/bash

[ "$(/var/ossec/bin/wazuh-control status | grep -E 'clusterd is running|apid is running' | wc -l)" == 2 ] || exit 1
exit 0
