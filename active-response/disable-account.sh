#!/bin/sh
# Disable an account by setting "passwd -l"
# Requirements: System with a passwd that supports -l and -u
# Expect: username (can't be "root")
# Author: Daniel B. Cid
# Last modified: Jan 13, 2005

UNAME=`uname`
PASSWD="/usr/bin/passwd"
ACTION=$1
USER=$2
IP=$3

# We should only run on linux
if [ "X${UNAME}" != "XLinux" ]; then
   exit 0;
fi

# Checking if iptables is present
ls ${PASSWD} >> /dev/null 2>&1
if [ $? != 0 ]; then
    exit 0;
fi    
       
if [ "x${USER}" = "x" ]; then
   echo "$0: <username>" 
   exit 1;
fi


# Disabling an account
if [ "x${ACTION}" = "xadd" ]; then
   ${PASSWD} -l ${USER}
   exit 0;

# Removing IP block
elif [ "x${ACTION}" = "xdelete" ]; then
   ${PASSWD} -u ${USER}
   exit 0;

# Invalid action
else
   echo "$0: invalid action: ${ACTION}"
fi
       

exit 1;
