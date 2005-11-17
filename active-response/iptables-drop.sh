#!/bin/sh
# Adds an IP to the iptables drop list
# Requirements: Linux with iptables installed
# Expect: srcip
# Author: Daniel B. Cid
# Last modified: Nov 11, 2005

UNAME=`uname`
IPTABLES="/sbin/iptables"
USER=$1
IP=$2

# We should only run on linux
if [ "X${UNAME}" != "XLinux" ]; then
   exit 0;
fi

# Checking if iptables is present
ls ${IPTABLES} >> /dev/null 2>&1
if [ $? != 0 ]; then
   exit 0;
fi    
       
if [ "x${IP}" = "x" ]; then
   echo "$0: <username> <ip>" 
   exit 1;
fi

${IPTABLES} -I INPUT -s ${IP} -j DROP
exit 0;
