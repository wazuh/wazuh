#!/bin/sh
# Extract key
# by Pedro S. Wazuh.com

ID=$1

if [ $# -ne 1 ]; then
    echo $0:  Invalid  arguments number.
    exit 1
fi

# Extract key
KEY="$(/var/ossec/bin/manage_agents manage_agents -e $ID | tail -1)"
echo "{ \"key\": \"${KEY}\"}"
