#!/bin/sh
# Adds an IP to the firewalld drop list
# Requirements: Linux with firewalld
# Expect: srcip
# Author: Daniel B. Cid (iptables)
# Author: cgzones 
# Author: ChristianBeer
# Last modified: Oct 23, 2014

UNAME=`uname`
ECHO="/bin/echo"
GREP="/bin/grep"
FWDCMD="/bin/firewall-cmd"
RULE=""
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
    *:* ) RULE="rule family='ipv6' source address='${IP}' drop";;
    *.* ) RULE="rule family='ipv4' source address='${IP}' drop";;
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
            # Lock aquired (setting the pid)
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

        # Sleep 1 after 10/25 interactions
        if [ "$i" = "10" -o "$i" = "25" ]; then
            sleep 1;
        fi

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
      ARG1="--add-rich-rule="
   else
      ARG1="--remove-rich-rule="
   fi

   # Checking if firewall-cmd is present
   if [ ! -x ${FWDCMD} ]; then
      FWDCMD="/usr"${FWDCMD}
      if [ ! -x ${FWDCMD} ]; then
        echo "$0: can not find firewall-cmd"
        exit 1;
      fi
   fi

   # Executing and exiting
   COUNT=0;
   lock;
   while [ 1 ]; do
        ${FWDCMD} ${ARG1}"${RULE}" >/dev/null
        RES=$?
        if [ $RES = 0 ]; then
            break;
        else
            COUNT=`expr $COUNT + 1`;
            echo "`date` Unable to run (firewall-cmd returning != $RES): $COUNT - $0 $1 $2 $3 $4 $5" >> ${LOG_FILE}
            sleep $COUNT;

            if [ $COUNT -gt 4 ]; then
                break;
            fi    
        fi
   done
   unlock;

   exit 0;
else
   exit 0;
fi
