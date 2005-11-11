#!/bin/sh
# Adds an IP to the iptables drop list
# Requirements: Linux with iptables installed
# Author: Daniel B. Cid
# Last modified: Nov 11, 2005


IPTABLES="/sbin/iptables"
USER=$1
IP=$2

if [ "x${IP}" = "x" ]; then
   echo "$0: Missing argument (ip)" 
   exit 1;
fi

${IPTABLES} -I INPUT -s ${IP} -j DROP
exit 0;
