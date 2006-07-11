#!/bin/sh
# ossec-control        This shell script takes care of starting
#                      or stopping ossec-hids
# Author: Daniel B. Cid <daniel.cid@gmail.com>


LOCAL=`dirname $0`;
cd ${LOCAL}
PWD=`pwd`
DIR=`dirname $PWD`;
cd $OLDPWD >/dev/null 2>&1;

###  Do not modify bellow here ###
NAME="OSSEC HIDS"
VERSION="v0.9"
AUTHOR="Daniel B. Cid"
DAEMONS="ossec-logcollector ossec-syscheckd ossec-analysisd ossec-maild ossec-execd"


## Locking for the start/stop
LOCK="${DIR}/var/start-script-lock"
LOCK_PID="${LOCK}/pid"


# This number should be more than enough (even if it is
# started multiple times together). It will try for up
# to 10 attempts (or 10 seconds) to execute.
MAX_ITERATION="10"


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

        # Waiting 1 second before trying again
        sleep 1;
        i=`expr $i + 1`;

        # If PID is not present, speed things a bit.
        kill -0 `cat ${LOCK_PID}` >/dev/null 2>&1
        if [ ! $? = 0 ]; then
            # Pid is not present.
            i=`expr $i + 1`;
        fi    

        # We tried 10 times to acquire the lock.
        if [ "$i" = "${MAX_ITERATION}" ]; then
            # Unlocking and executing
            unlock;
            mkdir ${LOCK} > /dev/null 2>&1
            echo "$$" > ${LOCK_PID}
            return;
        fi
    done
}


# Unlock function
unlock()
{
    rm -rf ${LOCK}
}

    
# Help message
help()
{
    # Help message
    echo "Usage: $0 {start|stop|restart|status}";
    exit 1;
}


# Status function
status()
{
    for i in ${DAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
            echo "${i} not running..."
        else
            echo "${i} is running..."
        fi
    done             
}


# Start function
start()
{
    SDAEMONS="ossec-maild ossec-execd ossec-analysisd ossec-logcollector ossec-syscheckd"
    
    echo "Starting $NAME $VERSION (by $AUTHOR)..."
    lock;

    # We first loop to check the config. 
    for i in ${SDAEMONS}; do
        ${DIR}/bin/${i} -t;
        if [ $? != 0 ]; then
            echo "${i}: Configuration error. Exiting"
            unlock;
            exit 1;
        fi    
    done
    
    # We actually start them now.
    for i in ${SDAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
            ${DIR}/bin/${i};
            if [ $? != 0 ]; then
                unlock;
                exit 1;
            fi 

            echo "Started ${i}..."            
        else
            echo "${i} already running..."                
        fi    
    
    done    

    # After we start we give 2 seconds for the daemons
    # to internally create their PID files.
    sleep 2;
    unlock;
    echo "Completed."
}

# Process status
pstatus()
{
    pfile=$1;
    
    # pfile must be set
    if [ "X${pfile}" = "X" ]; then
        return 0;
    fi
        
    ls ${DIR}/var/run/${pfile}*.pid > /dev/null 2>&1
    if [ $? = 0 ]; then
        kill -0 `cat ${DIR}/var/run/${pfile}*.pid` > /dev/null 2>&1
        if [ $? = 0 ]; then
          return 1;  
        fi           
    fi
    
    return 0;    
}


# Stop all
stopa()
{
    lock;
    for i in ${DAEMONS}; do
        pstatus ${i};
        if [ $? = 1 ]; then
            echo "Killing ${i} .. ";
            kill `cat ${DIR}/var/run/${i}*.pid`;
        else
            echo "${i} not running .."; 
        fi
        
        rm -f ${DIR}/var/run/${i}*.pid
        
     done    
    
    unlock;
    echo "$NAME $VERSION Stopped"
}



### MAIN HERE ###


case "$1" in
  start)
	start
	;;
  stop) 
	stopa
	;;
  restart)
	stopa
	start
	;;
  status)
    status
	;;
  help)  
    help
    ;;
  *)
    help
esac
