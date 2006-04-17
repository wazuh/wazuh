#!/bin/sh
# Adds an IP to the /etc/hosts.deny file
# Requirements: sshd and other binaries with tcp wrappers support
# Expect: srcip
# Author: Daniel B. Cid
# Last modified: Nov 09, 2005

ACTION=$1
USER=$2
IP=$3

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`
LOCK="${PWD}/host-deny-lock"
LOCK_PID="${PWD}/host-deny-lock/pid"
MAX_ITERATION="16"

echo "`date` $0 $1 $2 $3" >> /tmp/ossec-hids-responses.log

# IP Address must be provided
if [ "x${IP}" = "x" ]; then
   echo "$0: Missing argument <action> <user> (ip)" 
   exit 1;
fi


i=0;
# Providing a lock.
while [ 1 ]; do
    mkdir ${LOCK} > /dev/null 2>&1
    MSL=$?
    if [ "${MSL}" = "0" ]; then
        # Lock aquired (setting the pid)
        echo "$$" > ${LOCK_PID}
        break;
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
    i=`expr $i + 1`;
    
    # So i increments 2 by 2 if the pid does not change.
    # If the pid keeps changing, we will increments one
    # by one and fail after MAX_ITERACTION
    if [ "$i" = "${MAX_ITERATION}" ]; then
        echo "`date` Unable to execute. Locked: $0 $1 $2 $3"
                        >> /tmp/ossec-hids-responses.log
        # Unlocking
        rm -rf ${LOCK}                
        exit 1;                
    fi
done


# Adding the ip to hosts.deny
if [ "x${ACTION}" = "xadd" ]; then
   echo "ALL:${IP}" >> /etc/hosts.deny
   rm -rf ${LOCK}
   exit 0;


# Deleting from hosts.deny   
elif [ "x${ACTION}" = "xdelete" ]; then   
   cat /etc/hosts.deny | grep -v "ALL:${IP}"> /tmp/hosts.deny.$$
   mv /tmp/hosts.deny.$$ /etc/hosts.deny
   rm -rf ${LOCK}
   exit 0;


# Invalid action   
else
   echo "$0: invalid action: ${ACTION}"
   rm -rf ${LOCK}
fi       

exit 1;
