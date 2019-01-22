#!/bin/sh
# Restarts ossec.
# Requirements: none
# Copyright (C) 2015-2019, Wazuh Inc.
# Author: Daniel B. Cid

ACTION=$1
USER=$2
IP=$3

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`
UNAME=`uname`


# Logging the call
echo "`date` $0 $1 $2 $3 $4 $5" >> ${PWD}/../logs/active-responses.log



# Adding the ip to hosts.deny
if [ "x${ACTION}" = "xadd" ]; then
   ${PWD}/../bin/ossec-control restart
   exit 0;


# Deleting from hosts.deny   
elif [ "x${ACTION}" = "xdelete" ]; then   
   exit 0;


# Invalid action   
else
   echo "$0: invalid action: ${ACTION}"
fi       

exit 1;
