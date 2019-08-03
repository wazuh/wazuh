#!/bin/sh
# Disable an account by setting "passwd -l" or chuser
# Requirements: System with a passwd that supports -l and -u
#               or a system with chuser (AIX)
# Expect: username (can't be "root")
# Copyright (C) 2015-2019, Wazuh Inc.
# Authors: Ahmet Ozturk and Daniel B. Cid
# Last modified: Jan 19, 2005


UNAME=`uname`
PASSWD="/usr/bin/passwd"
CHUSER="/usr/bin/chuser"
ACTION=$1
USER=$2
IP=$3

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`
echo "`date` $0 $1 $2 $3 $4 $5" >> ${PWD}/../log/active-responses.log


if [ "x${USER}" = "x" ]; then
   echo "$0: [ add | delete ] <username>" 
   exit 1;
elif [ "x${USER}" = "xroot" ]; then
   echo "$0: Invalid username."
   exit 1;   
fi


# We should run on linux and on SunOS the passwd -u/-l
if [ "X${UNAME}" = "XLinux" -o "X${UNAME}" = "XSunOS" ]; then
   # Checking if passwd is present
   ls ${PASSWD} >> /dev/null 2>&1
   if [ $? != 0 ]; then
      exit 0;
   fi    

   CMD=${PASSWD}
   if [ "x${ACTION}" = "xadd" ]; then
       ARGS="-l"
   elif [ "x${ACTION}" = "xdelete" ]; then
       ARGS="-u"
   else
      echo "$0: invalid action: ${ACTION}"
      exit 1;
   fi


# On AIX, we run CHUSER
elif [ "X${UNAME}" = "XAIX" ]; then
   # Checking if chuser is present
   ls ${CHUSER} >> /dev/null 2>&1
   if [ $? != 0 ]; then
      exit 0;
   fi    

   CMD=${CHUSER}
    
   # Disabling an account
   if [ "x${ACTION}" = "xadd" ]; then
      ARGS="account_locked=true" 
   # Unblock the account 
   elif [ "x${ACTION}" = "xdelete" ]; then
      ARGS="account_locked=false"
   # Invalid action
   else
      echo "$0: invalid action: ${ACTION}"
      exit 1;
   fi


# We only support Linux, SunOS and AIX
else 
   exit 0;
fi


# Execute the command
${CMD} ${ARGS} ${USER}

exit 1;

