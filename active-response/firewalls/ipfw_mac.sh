#!/bin/sh
# Adds an IP to the IPFW drop list.
# Only works with IPFW.
# Expect: srcip
# Copyright (C) 2015-2019, Wazuh Inc.
# Author: Rafael Capovilla - under @ ( at ) underlinux.com.br
# Author: Daniel B. Cid - dcid @ ( at ) ossec.net
# Author: Charles W. Kefauver ckefauver @ ( at ) ibacom.es
#         changed for Mac OS X compatibility

UNAME=`uname`
IPFW="/sbin/ipfw"
ARG1=""
ARG2=""
ACTION=$1
USER=$2
IP=$3

# warning do NOT add leading 0 in SET_ID
SET_ID=2

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`
echo "`date` $0 $1 $2 $3 $4 $5" >> ${PWD}/../logs/active-responses.log


# Checking for an IP
if [ "x${IP}" = "x" ]; then
   echo "$0: <action> <username> <ip>" 
   exit 1;
fi

# Blocking IP
if [ "x${ACTION}" != "xadd" -a "x${ACTION}" != "xdelete" ]; then
   echo "$0: Invalid action: ${ACTION}"
   exit 1;
fi


# We should run on Darwin
if [ "X${UNAME}" = "XDarwin" ]; then
   ls ${IPFW} >> /dev/null 2>&1
   if [ $? != 0 ]; then
       exit 0;
   fi

   
   # Executing and exiting
	if [ "x${ACTION}" = "xadd" ]; then
	   #${IPFW} set disable ${SET_ID}
	   ${IPFW} -q add set ${SET_ID} deny ip from ${IP} to any
	   ${IPFW} -q add set ${SET_ID} deny ip from any to ${IP}
	   ${IPFW} -q set enable ${SET_ID}
	   exit 0;
	fi

	if [ "x${ACTION}" = "xdelete" ]; then
		#${IPFW} -S show | grep "set ${SET_ID}" | grep "${IP}"  >/dev/null 2>&1
		#get list of ipfw rules ID to delete
		RULES_TO_DELETE=`${IPFW} -S show | grep "set ${SET_ID}" | grep "${IP}" | awk '{print $1}'`
		
		for RULE_ID in ${RULES_TO_DELETE}
		do
			${IPFW} -q delete ${RULE_ID}
		done
		
		exit 0;
	fi

   exit 0;
fi


# Not Darwin
exit 1;

