#!/bin/sh

UNAME=`uname`
AFCTL="/Applications/Server.app/Contents/ServerRoot/usr/libexec/afctl"
ARG1=""
ARG2=""
ACTION=$1
USER=$2
IP=$3

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
   ls ${AFCTL} >> /dev/null 2>&1
   if [ $? != 0 ]; then
       exit 0;
   fi

   
   # Executing and exiting
	# set ttl for addition long enough (1000 min); ossec with default settings will delete the rule well before that and if it fails afctl will drop the rule in the end
	if [ "x${ACTION}" = "xadd" ]; then
	   ${AFCTL} -a ${IP} -t 1000
	   exit 0;
	fi

	if [ "x${ACTION}" = "xdelete" ]; then
		${AFCTL} -r ${IP}
		exit 0;
	fi

   exit 0;
fi


# Not Darwin
exit 1;
