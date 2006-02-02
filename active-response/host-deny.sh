#!/bin/sh
# Adds an IP to the /etc/hosts.deny file
# Requirements: sshd and other binaries with tcp wrappers support
# Expect: srcip
# Author: Daniel B. Cid
# Last modified: Nov 09, 2005

ACTION=$1
USER=$2
IP=$3

echo "`date` $0 $1 $2 $3" >> /tmp/ossec-hids-responses.log

# IP Address must be provided
if [ "x${IP}" = "x" ]; then
   echo "$0: Missing argument <action> <user> (ip)" 
   exit 1;
fi


# Adding the ip to hosts.deny
if [ "x${ACTION}" = "xadd" ]; then
   echo "ALL:${IP}" >> /etc/hosts.deny
   exit 0;


# Deleting from hosts.deny   
elif [ "x${ACTION}" = "xdelete" ]; then   
   cat /etc/hosts.deny | grep -v "ALL:${IP}"> /tmp/hosts.deny.$$
   mv /tmp/hosts.deny.$$ /etc/hosts.deny
   exit 0;


# Invalid action   
else
   echo "$0: invalid action: ${ACTION}"
fi       

exit 1;
