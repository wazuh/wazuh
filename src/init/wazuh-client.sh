#!/bin/sh

# Copyright (C) 2015, Wazuh Inc.
# wazuh-control        This shell script takes care of starting
#                      or stopping ossec-hids
# Author: Daniel B. Cid <daniel.cid@gmail.com>

LOCAL=`dirname $0`;
cd ${LOCAL}
PWD=`pwd`
DIR=`dirname $PWD`;

# Installation info
VERSION="v5.0.0"
REVISION="alpha0"
TYPE="agent"

###  Do not modify below here ###
AUTHOR="Wazuh Inc."
DAEMONS="wazuh-modulesd wazuh-logcollector wazuh-syscheckd wazuh-agentd wazuh-execd"

# Reverse order of daemons
SDAEMONS=$(echo $DAEMONS | awk '{ for (i=NF; i>1; i--) printf("%s ",$i); print $1; }')

## Locking for the start/stop
LOCK="${DIR}/var/start-script-lock"
LOCK_PID="${LOCK}/pid"

# This number should be more than enough (even if it is
# started multiple times together). It will try for up
# to 10 attempts (or 10 seconds) to execute.
MAX_ITERATION="60"

MAX_KILL_TRIES=300

checkpid()
{
    for i in ${DAEMONS}; do
        for j in `cat ${DIR}/var/run/${i}-*.pid 2>/dev/null`; do
            ps -p $j > /dev/null 2>&1
            if [ ! $? = 0 ]; then
                echo "Deleting PID file '${DIR}/var/run/${i}-${j}.pid' not used..."
                rm ${DIR}/var/run/${i}-${j}.pid
            fi
        done
    done
}

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

        # Waiting 1 second before trying again
        sleep 1;
        i=`expr $i + 1`;
        pid=$(cat ${LOCK_PID} 2>/dev/null)

        if [ $? = 0 ]
        then
            kill -0 ${pid} >/dev/null 2>&1
            if [ ! $? = 0 ]; then
                # Pid is not present.
                # Unlocking and executing
                unlock;
                mkdir ${LOCK} > /dev/null 2>&1
                echo "$$" > ${LOCK_PID}
                return;
            fi
        fi

        # We tried 10 times to acquire the lock.
        if [ "$i" = "${MAX_ITERATION}" ]; then
            echo "ERROR: Another instance is locking this process."
            echo "If you are sure that no other instance is running, please remove ${LOCK}"
            exit 1
        fi
    done
}

unlock()
{
    rm -rf ${LOCK}
}

help()
{
    # Help message
    echo "Usage: $0 {start|stop|restart|status|info [-v -r -t]}";
    exit 1;
}

status()
{
    RETVAL=0
    for i in ${DAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
            RETVAL=1
            echo "${i} not running..."
        else
            echo "${i} is running..."
        fi
    done
}

testconfig()
{
    # We first loop to check the config.
    for i in ${SDAEMONS}; do
        ${DIR}/bin/${i} -t;
        if [ $? != 0 ]; then
            echo "${i}: Configuration error. Exiting"
            unlock;
            exit 1;
        fi
    done
}

# Check folders
check_folders()
{
    ALERTS_FOLDER="../queue/alerts"

    if [ ! -d $ALERTS_FOLDER ]
    then
        if rm -rf $ALERTS_FOLDER && mkdir -p $ALERTS_FOLDER && chown wazuh:wazuh $ALERTS_FOLDER && chmod 770 $ALERTS_FOLDER
        then
            echo "WARNING: missing folder 'queue/alerts'. Restored back."
        else
            echo "ERROR: missing folder 'queue/alerts', and could not restore back."
            exit 1
        fi
    fi
}

# Start function
start_service()
{
    echo "Starting Wazuh $VERSION..."
    checkpid;

    # Delete all files in temporary folder
    TO_DELETE="$DIR/tmp/*"
    rm -rf $TO_DELETE

    # We actually start them now.
    for i in ${SDAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
            failed=false
            ${DIR}/bin/${i};
            if [ $? != 0 ]; then
                failed=true
            else
                j=0;
                while [ $failed = false ]; do
                    pstatus ${i};
                    if [ $? = 1 ]; then
                        break;
                    fi
                    sleep 1;
                    j=`expr $j + 1`;
                    if [ "$j" -ge "${MAX_ITERATION}" ]; then
                        failed=true
                    fi
                done
            fi
            if [ $failed = true ]; then
                echo "${i} did not start";
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
    echo "Completed."
}

pstatus()
{
    pfile=$1;

    # pfile must be set
    if [ "X${pfile}" = "X" ]; then
        return 0;
    fi

    ls ${DIR}/var/run/${pfile}-*.pid > /dev/null 2>&1
    if [ $? = 0 ]; then
        for pid in `cat ${DIR}/var/run/${pfile}-*.pid 2>/dev/null`; do
            ps -p ${pid} > /dev/null 2>&1
            if [ ! $? = 0 ]; then
                echo "${pfile}: Process ${pid} not used by Wazuh, removing .."
                rm -f ${DIR}/var/run/${pfile}-${pid}.pid
                continue;
            fi

            kill -0 ${pid} > /dev/null 2>&1
            if [ $? = 0 ]; then
                return 1;
            fi
        done
    fi

    return 0;
}

wait_pid() {
    wp_counter=1

    while kill -0 $1 2> /dev/null
    do
        if [ "$wp_counter" = "$MAX_KILL_TRIES" ]
        then
            return 1
        else
            # sleep doesn't work in AIX
            # read doesn't work in FreeBSD
            sleep 0.1 > /dev/null 2>&1 || read -t 0.1 > /dev/null 2>&1
            wp_counter=`expr $wp_counter + 1`
        fi
    done

    return 0
}

stop_service()
{
    checkpid;
    for i in ${DAEMONS}; do
        pstatus ${i};
        if [ $? = 1 ]; then
            echo "Killing ${i}... ";

            pid=`cat ${DIR}/var/run/${i}-*.pid`
            kill $pid

            if ! wait_pid $pid
            then
                echo "Process ${i} couldn't be terminated. It will be killed.";
                kill -9 $pid
            fi
        else
            echo "${i} not running...";
        fi

        rm -f ${DIR}/var/run/${i}-*.pid
     done

    echo "Wazuh $VERSION Stopped"
}

info()
{
     if [ "X${1}" = "X" ]; then
        echo "WAZUH_VERSION=\"${VERSION}\""
        echo "WAZUH_REVISION=\"${REVISION}\""
        echo "WAZUH_TYPE=\"${TYPE}\""
    else
        case "${1}" in
            -v) echo "${VERSION}" ;;
            -r) echo "${REVISION}" ;;
            -t) echo "${TYPE}" ;;
             *) echo "Invalid flag: ${1}" && help ;;
        esac
    fi
}

restart_service()
{
    testconfig
    lock
    stop_service
    sleep 1
    start_service
    unlock
}

### MAIN HERE ###

arg=$2

case "$1" in
start)
    testconfig
    check_folders
    lock
    start_service
    unlock
    ;;
stop)
    lock
    stop_service
    unlock
    ;;
restart)
    restart_service
    ;;
reload)
    DAEMONS=$(echo $DAEMONS | sed 's/wazuh-agentd//')
    restart_service
    # Signal agentd (SIGUSR1) to reload (reconnects execd)
    pid=`cat ${DIR}/var/run/wazuh-agentd-*.pid`
    kill -USR1 $pid
    ;;
status)
    lock
    status
    unlock
    ;;
info)
    info $arg
    ;;
help)
    help
    ;;
*)
    help
esac

exit $RETVAL
