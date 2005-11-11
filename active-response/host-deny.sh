#!/bin/sh
# Adds an IP to the /etc/hosts.deny file
# Requirements: sshd and other binaries with tcp wrappers support
# Author: Daniel B. Cid
# Last modified: Nov 09, 2005


USER=$1
IP=$2

if [ "x${IP}" = "x" ]; then
   echo "$0: Missing argument (ip)" 
   exit 1;
fi

echo "ALL:${IP}" >> /etc/hosts.deny
exit 0;
