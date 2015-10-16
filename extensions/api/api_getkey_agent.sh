#!/bin/sh
# Extract key
# by Pedro S. Wazuh.com

ID=$1

if [ $# -ne 1 ]; then
    echo $0:  Invalid  arguments number.
    exit 1
fi

# Extract key
KEY="$(/var/ossec/bin/manage_agents manage_agents -e $ID | tail -1 | grep -v "Invalid")"

if [ ! -z "$KEY" ]; then
	echo "{\"response\": {\"key\": \"${KEY}\"},\"error\": 0}"
else
	echo "{\"response\": \"\",\"error\": 1,\"description\": \"Invalid ID '$1' given. ID is not present.\"}"
fi
