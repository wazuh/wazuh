#!/bin/sh
# Adds an IP to the iptables drop list (if linux)
# Adds an IP to the ipfilter drop list (if solaris, freebsd or netbsd)
# Adds an IP to the ipsec drop list (if aix)
# Requirements: Linux with iptables, Solaris/FreeBSD/NetBSD with ipfilter or AIX with IPSec
# Expect: srcip
# Copyright (C) 2015-2019, Wazuh Inc.
# Author: Ahmet Ozturk (ipfilter and IPSec)
# Author: Daniel B. Cid (iptables)
# Author: cgzones

UNAME=`uname`
ECHO="/bin/echo"
GREP="/bin/grep"
IPTABLES=""
IP4TABLES="/sbin/iptables"
IP6TABLES="/sbin/ip6tables"
IPFILTER="/sbin/ipf"
if [ "X$UNAME" = "XSunOS" ]; then
    IPFILTER="/usr/sbin/ipf"
fi    
GENFILT="/usr/sbin/genfilt"
LSFILT="/usr/sbin/lsfilt"
MKFILT="/usr/sbin/mkfilt"
RMFILT="/usr/sbin/rmfilt"
ARG1=""
ARG2=""
RULEID=""
ACTION=$1
USER=$2
IP=$3
PWD=`pwd`
LOCK="${PWD}/fw-drop"
LOCK_PID="${PWD}/fw-drop/pid"


LOCAL=`dirname $0`;
cd $LOCAL
cd ../
filename=$(basename "$0")

LOG_FILE="${PWD}/../logs/active-responses.log"

echo "`date` $0 $1 $2 $3 $4 $5" >> ${LOG_FILE}


# Checking for an IP
if [ "x${IP}" = "x" ]; then
   echo "$0: <action> <username> <ip>" 
   exit 1;
fi

case "${IP}" in
    *:* ) IPTABLES=$IP6TABLES;;
    *.* ) IPTABLES=$IP4TABLES;;
    * ) echo "`date` Unable to run active response (invalid IP: '${IP}')." >> ${LOG_FILE} && exit 1;;
esac

# This number should be more than enough (even if a hundred
# instances of this script is ran together). If you have
# a really loaded env, you can increase it to 75 or 100.
MAX_ITERATION="50"

# Lock function
lock()
{
    i=0;
    # Providing a lock.
    while [ 1 ]; do
        mkdir ${LOCK} > /dev/null 2>&1
        MSL=$?
        if [ "${MSL}" = "0" ]; then
            # Lock acquired (setting the pid)
            echo "$$" > ${LOCK_PID}
            return;
        fi

        # Getting currently/saved PID locking the file
        C_PID=`cat ${LOCK_PID} 2>/dev/null`
        if [ "x" = "x${S_PID}" ]; then
            S_PID=${C_PID}
        fi

        # Breaking out of the loop after X attempts
        if [ "x${C_PID}" = "x${S_PID}" ]; then
            i=`expr $i + 1`;
        fi

        sleep $i;

        i=`expr $i + 1`;

        # So i increments 2 by 2 if the pid does not change.
        # If the pid keeps changing, we will increments one
        # by one and fail after MAX_ITERACTION

        if [ "$i" = "${MAX_ITERATION}" ]; then
            kill="false"
            for pid in `pgrep -f "${filename}"`; do
                if [ "x${pid}" = "x${C_PID}" ]; then
                    # Unlocking and exiting
                    kill -9 ${C_PID}
                    echo "`date` Killed process ${C_PID} holding lock." >> ${LOG_FILE}
                    kill="true"
                    unlock;
                    i=0;
                    S_PID="";
                    break;
                fi
            done

            if [ "x${kill}" = "xfalse" ]; then
                echo "`date` Unable kill process ${C_PID} holding lock." >> ${LOG_FILE}
                # Unlocking and exiting
                unlock;
                exit 1;
            fi
        fi
    done
}

# Unlock function
unlock()
{
   rm -rf ${LOCK} 
}



# Blocking IP
if [ "x${ACTION}" != "xadd" -a "x${ACTION}" != "xdelete" ]; then
   echo "$0: invalid action: ${ACTION}"
   exit 1;
fi



# We should run on linux
if [ "X${UNAME}" = "XLinux" ]; then
   if [ "x${ACTION}" = "xadd" ]; then
      ARG1="-I INPUT -s ${IP} -j DROP"
      ARG2="-I FORWARD -s ${IP} -j DROP"
   else
      ARG1="-D INPUT -s ${IP} -j DROP"
      ARG2="-D FORWARD -s ${IP} -j DROP"
   fi
   
   # Checking if iptables is present
   if [ ! -x ${IPTABLES} ]; then
      IPTABLES="/usr"${IPTABLES}
      if [ ! -x ${IPTABLES} ]; then
        echo "$0: can not find iptables"
        exit 0;
      fi
   fi

   # Executing and exiting
   COUNT=0;
   lock;
   while [ 1 ]; do
        ${IPTABLES} ${ARG1}
        RES=$?
        if [ $RES = 0 ]; then
            break;
        else
            COUNT=`expr $COUNT + 1`;
            echo "`date` Unable to run (iptables returning != $RES): $COUNT - $0 $1 $2 $3 $4 $5" >> ${LOG_FILE}
            sleep $COUNT;

            if [ $COUNT -gt 4 ]; then
                break;
            fi    
        fi
   done
   
   COUNT=0;
   while [ 1 ]; do
        ${IPTABLES} ${ARG2}
        RES=$?
        if [ $RES = 0 ]; then
            break;
        else
            COUNT=`expr $COUNT + 1`;
            echo "`date` Unable to run (iptables returning != $RES): $COUNT - $0 $1 $2 $3 $4 $5" >> ${LOG_FILE}
            sleep $COUNT;

            if [ $COUNT -gt 4 ]; then
                break;
            fi       
        fi
   done
   unlock;
            
   exit 0;
   
# FreeBSD, SunOS or NetBSD with ipfilter
elif [ "X${UNAME}" = "XFreeBSD" -o "X${UNAME}" = "XSunOS" -o "X${UNAME}" = "XNetBSD" ]; then
   
   # Checking if ipfilter is present
   ls ${IPFILTER} >> /dev/null 2>&1
   if [ $? != 0 ]; then
      exit 0;
   fi    

   # Checking if echo is present
   ls ${ECHO} >> /dev/null 2>&1
   if [ $? != 0 ]; then
       exit 0;
   fi    
   
   if [ "x${ACTION}" = "xadd" ]; then
      ARG1="\"@1 block out quick from any to ${IP}\""
      ARG2="\"@1 block in quick from ${IP} to any\""
      IPFARG="${IPFILTER} -f -"
   else
      ARG1="\"@1 block out quick from any to ${IP}\""
      ARG2="\"@1 block in quick from ${IP} to any\""
      IPFARG="${IPFILTER} -rf -"
   fi
  
   # Executing it 
   eval ${ECHO} ${ARG1}| ${IPFARG}       
   eval ${ECHO} ${ARG2}| ${IPFARG}
   
   exit 0;

# AIX with ipsec
elif [ "X${UNAME}" = "XAIX" ]; then

  # Checking if genfilt is present
  ls ${GENFILT} >> /dev/null 2>&1
  if [ $? != 0 ]; then
     exit 0;
  fi
         
  # Checking if lsfilt is present
  ls ${LSFILT} >> /dev/null 2>&1
  if [ $? != 0 ]; then
     exit 0;
  fi
  # Checking if mkfilt is present
  ls ${MKFILT} >> /dev/null 2>&1
  if [ $? != 0 ]; then
     exit 0;
  fi
         
  # Checking if rmfilt is present
  ls ${RMFILT} >> /dev/null 2>&1
  if [ $? != 0 ]; then
     exit 0;
  fi

  if [ "x${ACTION}" = "xadd" ]; then
    ARG1=" -v 4 -a D -s ${IP} -m 255.255.255.255 -d 0.0.0.0 -M 0.0.0.0 -w B -D \"Access Denied by OSSEC-HIDS\"" 
    #Add filter to rule table
    eval ${GENFILT} ${ARG1}
    
    #Deactivate  and activate the filter rules.
    eval ${MKFILT} -v 4 -d
    eval ${MKFILT} -v 4 -u
  else
    # removing a specific rule is not so easy :(
     eval ${LSFILT} -v 4 -O  | ${GREP} ${IP} | 
     while read -r LINE
     do
         RULEID=`${ECHO} ${LINE} | cut -f 1 -d "|"`
         let RULEID=${RULEID}+1
         ARG1=" -v 4 -n ${RULEID}"
         eval ${RMFILT} ${ARG1}
     done
    #Deactivate  and activate the filter rules.
    eval ${MKFILT} -v 4 -d
    eval ${MKFILT} -v 4 -u
  fi

else
    exit 0;
fi
