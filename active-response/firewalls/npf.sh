#!/bin/sh
# Copyright (C) 2015-2019, Wazuh Inc.
# Author: Gianni D'Aprile

GREP=`which grep`

ACTION=$1
USER=$2
IP=$3

# Finding path
LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`
echo "`date` $0 $1 $2 $3 $4 $5" >> ${PWD}/../logs/active-responses.log

NPFCTL=/sbin/npfctl

if [ ! -x ${NPFCTL} ]; then
	echo "$0: NPF not present."
	echo "$0: NPF not present." >> ${PWD}/ossec-hids-responses.log
	exit 0;
fi

NPF_ACTIVE=`${NPFCTL} show | grep "filtering:" | ${GREP} -c active`

if [ "x1" != "x${NPF_ACTIVE}" ]; then
	echo "$0: NPF not active."
	echo "$0: NPF not active." >> ${PWD}/ossec-hids-responses.log
	exit 0;
fi

NPF_OSSEC_READY=`${NPFCTL} show | ${GREP} -c "table <ossec_blacklist>"`

if [ "x1" != "x${NPF_OSSEC_READY}" ]; then
	echo "$0: NPF not configured."
	echo "$0: NPF not configured." >> ${PWD}/ossec-hids-responses.log
	exit 0;
fi

# Checking for an IP
if [ "x${IP}" = "x" ]; then
   echo "$0: <action> <username> <ip>" 
   exit 1;
fi

case "x${ACTION}" in

	xadd)

	${NPFCTL} table ossec_blacklist add ${IP} >/dev/null 2>&1
	exit 0

	;;

	xdelete)

	${NPFCTL} table ossec_blacklist del ${IP} >/dev/null 2>&1
	exit 0

	;;

	*)

	echo "$0: invalid action: ${ACTION}"
	echo "$0: invalid action: ${ACTION}" >> ${PWD}/ossec-hids-responses.log
 	exit 1

	;;

esac