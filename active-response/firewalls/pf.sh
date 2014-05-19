#!/bin/sh
# Author: Rafael M. Capovilla
# Last modified: Daniel B. Cid

UNAME=`uname`
GREP=`which grep`
PFCTL="/sbin/pfctl"

# Getting pf rules file.
PFCTL_RULES=`${GREP} pf_rules /etc/rc.conf | awk -F"=" '{print $2}' | awk '{print $1}' | awk -F"\"" '{print $1 $2}'`
if [ "X${PFCTL_RULES}" = "X" ]; then
    PFCTL_RULES="/etc/pf.conf"
fi    

# Checking if ossec table is configured
PFCTL_TABLE=`cat ${PFCTL_RULES} | egrep -v "(^#|^$)" | grep ossec_fwtable | head -1 | awk '{print $2}' | sed "s/<//;s/>//"`
ARG1=""
ACTION=$1
USER=$2
IP=$3


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
		else
	     		ARG1="-t $PFCTL_TABLE -T delete ${IP}"
		fi
	fi
  else
	exit 0;
  fi

  #Executing it
  ${PFCTL} ${ARG1} > /dev/null 2>&1 

  exit 0;
  
else
    exit 0;
fi
