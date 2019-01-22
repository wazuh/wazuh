#!/bin/sh

# Renumber (change IP address) an OSSEC agent (must be run on both agent 
# and server)
# Copyright (C) 2015-2019, Wazuh Inc.

# Sanity checks

if [ $# -ne 2 ]; then
	echo Usage:  $0 agent-name new-IP-address
	exit 1
fi

if ! [ -e /etc/ossec-init.conf ]; then
	echo ossec-init.conf not found. Exiting...
	exit 1
fi

. /etc/ossec-init.conf
KEYFILE=$DIRECTORY/etc/client.keys

# Get the IP address from the key file
IPADDR=`grep -w "${1}" $KEYFILE | cut -d " " -f 3`
if [ -z ${IPADDR} ]; then
	echo Agent ${1} not found. Exiting...
	exit 1
fi

# stop OSSEC
/var/ossec/bin/ossec-control stop

# Update the key record
sed -i $KEYFILE -e "s/${IPADDR}/${2}/"

# Rename files and directories (manager)

cd $DIRECTORY/queue

if [ -e "agent-info/${1}-${IPADDR}" ]; then
	mv "agent-info/${1}-${IPADDR}" \
	   "agent-info/${1}-${2}"
fi

if [ -e "rootcheck/(${1}) ${IPADDR}->rootcheck" ]; then
	mv "rootcheck/(${1}) ${IPADDR}->rootcheck" \
	   "rootcheck/(${1}) ${2}->rootcheck"
fi

if [ -e "syscheck/(${1}) ${IPADDR}->syscheck" ]; then
	mv "syscheck/(${1}) ${IPADDR}->syscheck" \
	   "syscheck/(${1}) ${2}->syscheck"
fi

if [ -e "syscheck/.(${1}) ${IPADDR}->syscheck.cpt" ]; then
	mv "syscheck/.(${1}) ${IPADDR}->syscheck.cpt" \
	   "syscheck/.(${1}) ${2}->syscheck.cpt"
fi

# Restart OSSEC
/var/ossec/bin/ossec-control start
