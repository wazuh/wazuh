#!/bin/sh

# Copyright (C) 2015, Wazuh Inc.
# wazuh-control        This shell script takes care of starting
#                      or stopping ossec-hids
# Author: Daniel B. Cid <daniel.cid@gmail.com>

# Getting where we are installed
LOCAL=`dirname $0`;
cd ${LOCAL}
PWD=`pwd`
DIR=`dirname $PWD`;
PLIST=${DIR}/bin/.process_list;

# Installation info
VERSION="v4.13.0"
REVISION="rc1"
TYPE="local"

###  Do not modify below here ###

# Getting additional processes
ls -la ${PLIST} > /dev/null 2>&1
if [ $? = 0 ]; then
. ${PLIST};
fi

AUTHOR="Wazuh Inc."
DAEMONS="wazuh-modulesd wazuh-monitord wazuh-logcollector wazuh-syscheckd wazuh-analysisd wazuh-maild wazuh-execd wazuh-db wazuh-agentlessd wazuh-integratord wazuh-dbd wazuh-csyslogd"

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

checkpid() {
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

lock() {
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
    echo ""
    echo "Usage: $0 {start|stop|restart|status|enable|disable|info [-v -r -t]}";
    exit 1;
}

DATABASE_MSG="This option is deprecated because the database output is now enabled by default."
SYSLOG_MSG="This option is deprecated because Client Syslog is now enabled by default."
AGENTLESS_MSG="This option is deprecated because Agentless is now enabled by default."
INTEGRATOR_MSG="This option is deprecated because Integrator is now enabled by default."


# Enables additional daemons
enable()
{
    if [ "X$2" = "X" ]; then
        echo ""
        echo "Enable options: debug"
        echo "Usage: $0 enable debug"
        exit 1;
    fi

    if [ "X$2" = "Xdatabase" ]; then
        echo "$DATABASE_MSG"
    elif [ "X$2" = "Xclient-syslog" ]; then
        echo "$SYSLOG_MSG"
    elif [ "X$2" = "Xagentless" ]; then
        echo "$AGENTLESS_MSG";
    elif [ "X$2" = "Xintegrator" ]; then
        echo "$INTEGRATOR_MSG";
    elif [ "X$2" = "Xdebug" ]; then
        echo "DEBUG_CLI=\"-d\"" >> ${PLIST};
    else
        echo ""
        echo "Invalid enable option."
        echo ""
        echo "Enable options: debug"
        echo "Usage: $0 enable debug"
        exit 1;
    fi
}

# Disables additional daemons
disable()
{
    if [ "X$2" = "X" ]; then
        echo ""
        echo "Disable options: debug"
        echo "Usage: $0 disable debug"
        exit 1;
    fi
    daemon=''


    if [ "X$2" = "Xdatabase" ]; then
        echo "$DATABASE_MSG"
    elif [ "X$2" = "Xclient-syslog" ]; then
        echo "$SYSLOG_MSG"
    elif [ "X$2" = "Xagentless" ]; then
        echo "$AGENTLESS_MSG";
    elif [ "X$2" = "Xintegrator" ]; then
        echo "$INTEGRATOR_MSG";
    elif [ "X$2" = "Xdebug" ]; then
        echo "DEBUG_CLI=\"\"" >> ${PLIST};
    else
        echo ""
        echo "Invalid disable option."
        echo ""
        echo "Disable options: debug"
        echo "Usage: $0 disable debug"
        exit 1;
    fi
    if [ "$daemon" != '' ]; then
        pstatus ${daemon};
        if [ $? = 1 ]; then
            kill `cat $DIR/var/run/$daemon-*`
            rm $DIR/var/run/$daemon-*
            echo "Killing ${daemon}...";
        fi
    fi
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
    # We first loop to check the config
    for i in ${SDAEMONS}; do
        ${DIR}/bin/${i} -t ${DEBUG_CLI};
        if [ $? != 0 ]; then
            if [ ! -f ${DIR}/var/run/.restart ]; then
                touch ${DIR}/var/run/${i}.failed
            fi
            echo "${i}: Configuration error. Exiting"
            rm -f ${DIR}/var/run/*.start
            rm -f ${DIR}/var/run/.restart
            unlock;
            exit 1;
        fi
    done
}

start_service()
{
    echo "Starting Wazuh $VERSION..."
    TEST=$(${DIR}/bin/wazuh-logtest-legacy -t  2>&1)
    echo $TEST

    if [ ! -z "$TEST" ]; then
        echo "wazuh-analysisd: Configuration error. Exiting."
        touch ${DIR}/var/run/wazuh-analysisd.failed
        exit 1;
    fi

    checkpid;

    # Delete all files in temporary folder
    TO_DELETE="$DIR/tmp"
    find $TO_DELETE -mindepth 1 -not -path "$TO_DELETE/vd_*_vd_*.tar" -not -path "$TO_DELETE/vd_*_vd_*.tar.xz" -delete

    # We actually start them now.
    for i in ${SDAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
            rm -f ${DIR}/var/run/${i}.failed
            touch ${DIR}/var/run/${i}.start
            ${DIR}/bin/${i} ${DEBUG_CLI};
            if [ $? != 0 ]; then
                echo "${i} did not start correctly.";
                rm -f ${DIR}/var/run/${i}.start
                touch ${DIR}/var/run/${i}.failed
                rm -f ${DIR}/var/run/*.start
                rm -f ${DIR}/var/run/.restart
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
    rm -f ${DIR}/var/run/*.start
    ls -la "${DIR}/ossec-agent/" >/dev/null 2>&1
    if [ $? = 0 ]; then
        echo ""
        echo "Starting sub agent directory (for hybrid mode)"
        ${DIR}/ossec-agent/bin/wazuh-control start
    fi

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
                echo "${pfile}: Process ${pid} not used by Wazuh, removing..."
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
            echo "Killing ${i}...";
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


    ls -la "${DIR}/ossec-agent/" >/dev/null 2>&1
    if [ $? = 0 ]; then
        echo ""
        echo "Stopping sub agent directory (for hybrid mode)"
        ${DIR}/ossec-agent/bin/wazuh-control stop
    fi
    echo "Wazuh $VERSION Stopped"
}

info()
{
    if [ "X${1}" = "X" ]; then
        echo "WAZUH_VERSION=\"${VERSION}\""
        echo "WAZUH_REVISION=\"${REVISION}\""
        echo "WAZUH_TYPE=\"${TYPE}\""
    else
        case ${1} in
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
    start_service
    unlock
}

### MAIN HERE ###

arg=$2

case "$1" in
start)
    testconfig
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
    DAEMONS=$(echo $DAEMONS | sed 's/wazuh-execd//')
    restart_service
    ;;
status)
    lock
    status
    unlock
    ;;
enable)
    lock
    enable $1 $2;
    unlock
    ;;
disable)
    lock
    disable $1 $2;
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
