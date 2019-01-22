#!/bin/sh
# Custom OSSEC block / Easily modifiable for custom responses (touch a file, insert to db, etc).
# Expect: srcip
# Copyright (C) 2015-2019, Wazuh Inc.
# Author: Daniel B. Cid
# Last modified: Feb 16, 2013

ACTION=$1
USER=$2
IP=$3

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`


# Logging the call
echo "`date` $0 $1 $2 $3 $4 $5" >> ${PWD}/../logs/active-responses.log


# IP Address must be provided
if [ "x${IP}" = "x" ]; then
   echo "$0: Missing argument <action> <user> (ip)" 
   exit 1;
fi


# Custom block (touching a file inside /ipblock/IP)
if [ "x${ACTION}" = "xadd" ]; then
    if [ ! -d /ipblock ]; then
       mkdir /ipblock
    fi
    touch "/ipblock/${IP}"
elif [ "x${ACTION}" = "xdelete" ]; then   
    rm -f "/ipblock/${IP}"

# Invalid action   
else
   echo "$0: invalid action: ${ACTION}"
fi       

exit 1;
