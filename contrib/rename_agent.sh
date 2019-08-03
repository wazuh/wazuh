#!/bin/sh

# Rename an OSSEC agent (must be run on both agent and server)
# Copyright (C) 2015-2019, Wazuh Inc.

# Sanity checks

if [ $# -ne 2 ]; then
	echo Usage:  $0 old-name new-name
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
sed -i $KEYFILE -e "s/${1}/${2}/"

# Rename files and directories (manager)

cd $DIRECTORY/queue

if [ -e "agent-info/${1}-${IPADDR}" ]; then
	mv "agent-info/${1}-${IPADDR}" \
	   "agent-info/${2}-${IPADDR}"
fi

if [ -e "diff/${1}" ]; then
	mv "diff/${1}" \
	   "diff/${2}"
fi

if [ -e "rootcheck/(${1}) ${IPADDR}->rootcheck" ]; then
	mv "rootcheck/(${1}) ${IPADDR}->rootcheck" \
	   "rootcheck/(${2}) ${IPADDR}->rootcheck"
fi

if [ -e "syscheck/(${1}) ${IPADDR}->syscheck" ]; then
	mv "syscheck/(${1}) ${IPADDR}->syscheck" \
	   "syscheck/(${2}) ${IPADDR}->syscheck"
fi

if [ -e "syscheck/.(${1}) ${IPADDR}->syscheck.cpt" ]; then
	mv "syscheck/.(${1}) ${IPADDR}->syscheck.cpt" \
	   "syscheck/.(${2}) ${IPADDR}->syscheck.cpt"
fi

# Restart OSSEC
/var/ossec/bin/ossec-control start
