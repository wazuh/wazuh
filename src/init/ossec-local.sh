#!/bin/sh
# ossec-control        This shell script takes care of starting
#                      or stopping ossec-hids
# Author: Daniel B. Cid <daniel.cid@gmail.com>


LOCAL=`dirname $0`;
cd ${LOCAL}
PWD=`pwd`
DIR=`dirname $PWD`;
cd - >/dev/null;

###  Do not modify bellow here ###
NAME="OSSEC HIDS"
VERSION="v0.8"
AUTHOR="Daniel B. Cid"
DAEMONS="ossec-logcollector ossec-syscheckd ossec-analysisd ossec-maild ossec-execd"

    
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

    # We first loop to check the config. 
    for i in ${SDAEMONS}; do
        ${DIR}/bin/${i} -t;
        if [ $? != 0 ]; then
            echo "${i}: Configuration error. Exiting"
            exit 1;
        fi    
    done
    
    # We actually start them now.
    for i in ${SDAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
            ${DIR}/bin/${i};
            if [ $? != 0 ]; then
                exit 1;
            fi 

            echo "Started ${i}..."            
        else
            echo "${i} already running..."                
        fi    
    
    done    

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
    
    echo "$NAME $VERSION Stopped"
}



### MAIN HERE ###
WHO=`whoami`

if [ ! "X${WHO}" = "Xroot" ]; then
	echo "$0: You must be root to run this script"
	exit 1;
fi


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
