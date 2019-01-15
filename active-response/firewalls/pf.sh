#!/bin/sh
# Copyright (C) 2015-2019, Wazuh Inc.
# Author: Rafael M. Capovilla
# Last modified: Daniel B. Cid

UNAME=`uname`
GREP="/usr/bin/grep"
PFCTL="/sbin/pfctl"
PFCTL_RULES="/etc/pf.conf"
PFCTL_TABLE="ossec_fwtable"
ARG1=""
ARG2=""
CHECKTABLE=""
ACTION=$1
USER=$2
IP=$3

# Getting pf rules file.
if [ ! -f $PFCTL_RULES ]; then
        echo "The pf rules file $PFCTL_RULES does not exist"
        exit 1
fi 

# Checking if ossec table is configured
CHECKTABLE=`cat ${PFCTL_RULES} | $GREP $PFCTL_TABLE`
if [ -z "$CHECKTABLE" ]; then
        echo "Table $PFCTL_TABLE does not exist"
        exit 1
fi

# Finding path
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
   echo "$0: invalid action: ${ACTION}"
   echo "$0: invalid action: ${ACTION}" >> ${PWD}/ossec-hids-responses.log
   exit 1;
fi

# OpenBSD and FreeBSD pf
if [ "X${UNAME}" = "XOpenBSD" -o "X${UNAME}" = "XFreeBSD" -o "X${UNAME}" = "XDarwin" ]; then
  
  # Checking if pfctl is present
  ls ${PFCTL} > /dev/null 2>&1
  if [ ! $? = 0 ]; then
      echo "$0: PF not configured."
      echo "$0: PF not configured." >> ${PWD}/ossec-hids-responses.log
	  exit 0;
  fi

  # Checking if we have pf config file
  if [ -e ${PFCTL_RULES} ]; then
      
	#Checking if we got the table to add the bad guys
	if [ "x${PFCTL_TABLE}" = "x" ]; then
        echo "$0: PF not configured."
        echo "$0: PF not configured." >> ${PWD}/ossec-hids-responses.log
		exit 0;
	else
  		if [ "x${ACTION}" = "xadd" ]; then
	     		ARG1="-t $PFCTL_TABLE -T add ${IP}"
			ARG2="-k ${IP}"
		else
	     		ARG1="-t $PFCTL_TABLE -T delete ${IP}"
		fi
	fi
  else
	exit 0;
  fi

  #Executing it
  ${PFCTL} ${ARG1} > /dev/null 2>&1 
  ${PFCTL} ${ARG2} > /dev/null 2>&1
  exit 0;
  
else
    exit 0;
fi
