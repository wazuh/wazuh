#!/bin/sh
# Add agent. 
# by Pedro S. Wazuh.com

HOSTNAME=$1

if [ $# -ne 1 ]; then
    echo $0:  Invalid  arguments number.
    exit 1
fi

# Create bulk file
echo "any,$HOSTNAME" > /var/ossec/tmp/$HOSTNAME
# Add agent
ID="$(/var/ossec/bin/manage_agents -f tmp/$HOSTNAME | grep "ID:[0-9]*" | cut -d ':'  -f 2)"
if [ ! -z "$ID" ]; then
	echo "{\"response\": {\"ID\": \"${ID}\"},\"error\": 0}"
else
	echo "{\"response\": \"\",\"error\": 1,\"description\": \"Name '$1' already exits\"}"
fi
# Remove bulk file
rm -f /var/ossec/tmp/$HOSTNAME
