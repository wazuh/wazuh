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
MAX_ITERATION="5"

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

    # Breaking out of the loop after 5 attempts
    i=`expr $i + 1`;
    if [ "$i" = "${MAX_ITERATION}" ]; then
        echo "`date` Unable to execute. Locked: $0 $1 $2 $3"
                        >> /tmp/ossec-hids-responses.log
        # Unlocking
        rm -rf ${LOCK}                
        exit 1;                
    fi
    
    # Checking if the PID is still there 
    kill -0  `cat ${LOCK_PID}` >/dev/null 2>&1
    PSL=$?
    if [ "${PSL} = 0" ];
        # Locked
        sleep 1;        
    else
        break;    
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
