#!/bin/sh
# Adds an IP to the IPFW drop list.
# Only works with IPFW.
# We use TABLE 00001. If you use this table for anything else,
# please change it here.
# Expect: srcip
# Copyright (C) 2015-2019, Wazuh Inc.
# Author: Rafael Capovilla - under @ ( at ) underlinux.com.br
# Author: Daniel B. Cid - dcid @ ( at ) ossec.net
# Last modified: May 07, 2006

UNAME=`uname`
IPFW="/sbin/ipfw"
ARG1=""
ARG2=""
ACTION=$1
USER=$2
IP=$3
TABLE_ID=00001

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


# We should run on FreeBSD
# We always use table 00001 and rule id 00001.
if [ "X${UNAME}" = "XFreeBSD" ]; then
   ls ${IPFW} >> /dev/null 2>&1
   if [ $? != 0 ]; then
       exit 0;
   fi

   # Check if our table is set
   ${IPFW} show | grep "^00001" | grep "table(1)" >/dev/null 2>&1
   if [ ! $? = 0 ]; then
        # We need to add the table
        ${IPFW} -q 00001 add deny ip from table\(${TABLE_ID}\) to any
        ${IPFW} -q 00001 add deny ip from any to table\(${TABLE_ID}\)
   fi    
   
   
   # Executing and exiting
   ${IPFW} -q table ${TABLE_ID} ${ACTION} ${IP}

   exit 0;
fi


# Not FreeBSD
exit 1;
