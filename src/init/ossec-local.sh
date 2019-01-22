#!/bin/sh

# Copyright (C) 2015-2019, Wazuh Inc.
# ossec-control        This shell script takes care of starting
#                      or stopping ossec-hids
# Author: Daniel B. Cid <daniel.cid@gmail.com>

# Getting where we are installed
LOCAL=`dirname $0`;
cd ${LOCAL}
PWD=`pwd`
DIR=`dirname $PWD`;
PLIST=${DIR}/bin/.process_list;

###  Do not modify bellow here ###

# Getting additional processes
ls -la ${PLIST} > /dev/null 2>&1
if [ $? = 0 ]; then
. ${PLIST};
fi

AUTHOR="Wazuh Inc."
DAEMONS="wazuh-modulesd ossec-monitord ossec-logcollector ossec-syscheckd ossec-analysisd ossec-maild ossec-execd wazuh-db ${DB_DAEMON} ${CSYSLOG_DAEMON} ${AGENTLESS_DAEMON} ${INTEGRATOR_DAEMON}"
INITCONF="/etc/ossec-init.conf"

# Reverse order of daemons
SDAEMONS=$(echo $DAEMONS | awk '{ for (i=NF; i>1; i--) printf("%s ",$i); print $1; }')

[ -f ${INITCONF} ] && . ${INITCONF}  || echo "ERROR: No such file ${INITCONF}"

## Locking for the start/stop
LOCK="${DIR}/var/start-script-lock"
LOCK_PID="${LOCK}/pid"

# This number should be more than enough (even if it is
# started multiple times together). It will try for up
# to 10 attempts (or 10 seconds) to execute.
MAX_ITERATION="10"

MAX_KILL_TRIES=600

checkpid() {
    for i in ${DAEMONS}; do
        for j in `cat ${DIR}/var/run/${i}*.pid 2>/dev/null`; do
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
        pid=`cat ${LOCK_PID}` 2>/dev/null

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
    echo "Usage: $0 {start|stop|restart|status|enable|disable}";
    exit 1;
}

# Enables additional daemons
enable()
{
    if [ "X$2" = "X" ]; then
        echo ""
        echo "Enable options: database, client-syslog, agentless, debug, integrator"
        echo "Usage: $0 enable [database|client-syslog|agentless|debug|integrator]"
        exit 1;
    fi

    if [ "X$2" = "Xdatabase" ]; then
        echo "DB_DAEMON=ossec-dbd" >> ${PLIST};
    elif [ "X$2" = "Xclient-syslog" ]; then
        echo "CSYSLOG_DAEMON=ossec-csyslogd" >> ${PLIST};
    elif [ "X$2" = "Xagentless" ]; then
        echo "AGENTLESS_DAEMON=ossec-agentlessd" >> ${PLIST};
    elif [ "X$2" = "Xintegrator" ]; then
        echo "INTEGRATOR_DAEMON=ossec-integratord" >> ${PLIST};
    elif [ "X$2" = "Xdebug" ]; then
        echo "DEBUG_CLI=\"-d\"" >> ${PLIST};
    else
        echo ""
        echo "Invalid enable option."
        echo ""
        echo "Enable options: database, client-syslog, agentless, debug, integrator"
        echo "Usage: $0 enable [database|client-syslog|agentless|debug|integrator]"
        exit 1;
    fi
}

# Disables additional daemons
disable()
{
    if [ "X$2" = "X" ]; then
        echo ""
        echo "Disable options: database, client-syslog, agentless, debug, integrator"
        echo "Usage: $0 disable [database|client-syslog|agentless,debug|integrator]"
        exit 1;
    fi
    daemon=''
    if [ "X$2" = "Xdatabase" ]; then
        echo "DB_DAEMON=\"\"" >> ${PLIST};
        daemon='ossec-dbd'
    elif [ "X$2" = "Xclient-syslog" ]; then
        echo "CSYSLOG_DAEMON=\"\"" >> ${PLIST};
        daemon='ossec-csyslogd'
    elif [ "X$2" = "Xagentless" ]; then
        echo "AGENTLESS_DAEMON=\"\"" >> ${PLIST};
        daemon='ossec-agentlessd'
    elif [ "X$2" = "Xintegrator" ]; then
        echo "INTEGRATOR_DAEMON=\"\"" >> ${PLIST};
        daemon='ossec-integratord'
    elif [ "X$2" = "Xdebug" ]; then
        echo "DEBUG_CLI=\"\"" >> ${PLIST};
    else
        echo ""
        echo "Invalid disable option."
        echo ""
        echo "Disable options: database, client-syslog, agentless, debug, integrator"
        echo "Usage: $0 disable [database|client-syslog|agentless|debug|integrator]"
        exit 1;
    fi
    if [ "$daemon" != '' ]; then
        pstatus ${daemon};
        if [ $? = 1 ]; then
            kill `cat $DIR/var/run/$daemon*`
            rm $DIR/var/run/$daemon*
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
            echo "${i}: Configuration error. Exiting"
            unlock;
            exit 1;
        fi
    done
}

start()
{
    echo "Starting $NAME $VERSION..."
    TEST=$(${DIR}/bin/ossec-logtest -t  2>&1)
    echo $TEST
    if [ ! -z "$TEST" ]; then
        echo "ossec-analysisd: Configuration error. Exiting."
        exit 1;
    fi

    checkpid;

    # Delete all files in temporary folder
    TO_DELETE="$DIR/tmp/*"
    rm -rf $TO_DELETE


    # We actually start them now.
    for i in ${SDAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
            ${DIR}/bin/${i} ${DEBUG_CLI};
            if [ $? != 0 ]; then
                echo "${i} did not start correctly.";
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

    ls -la "${DIR}/ossec-agent/" >/dev/null 2>&1
    if [ $? = 0 ]; then
        echo ""
        echo "Starting sub agent directory (for hybrid mode)"
        ${DIR}/ossec-agent/bin/ossec-control start
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

    ls ${DIR}/var/run/${pfile}*.pid > /dev/null 2>&1
    if [ $? = 0 ]; then
        for j in `cat ${DIR}/var/run/${pfile}*.pid 2>/dev/null`; do
            ps -p $j > /dev/null 2>&1
            if [ ! $? = 0 ]; then
                echo "${pfile}: Process $j not used by ossec, removing..."
                rm -f ${DIR}/var/run/${pfile}-$j.pid
                continue;
            fi

            kill -0 $j > /dev/null 2>&1
            if [ $? = 0 ]; then
                return 1;
            fi
        done
    fi

    return 0;
}

wait_pid() {
    local i=1

    while kill -0 $1 2> /dev/null
    do
        if [ "$i" = "$MAX_KILL_TRIES" ]
        then
            return 1
        else
            # sleep doesn't work in AIX
            # read doesn't work in FreeBSD
            sleep 0.1 > /dev/null 2>&1 || read -t 0.1 > /dev/null 2>&1
            i=`expr $i + 1`
        fi
    done

    return 0
}

stopa()
{
    checkpid;
    for i in ${DAEMONS}; do
        pstatus ${i};
        if [ $? = 1 ]; then
            echo "Killing ${i}...";
            pid=`cat ${DIR}/var/run/${i}*.pid`
            kill $pid

            if ! wait_pid $pid
            then
                echo "Process ${i} couldn't be killed.";
            fi
        else
            echo "${i} not running...";
        fi
        rm -f ${DIR}/var/run/${i}*.pid
    done


    ls -la "${DIR}/ossec-agent/" >/dev/null 2>&1
    if [ $? = 0 ]; then
        echo ""
        echo "Stopping sub agent directory (for hybrid mode)"
        ${DIR}/ossec-agent/bin/ossec-control stop
    fi
    echo "$NAME $VERSION Stopped"
}

buildCDB()
{
    ${DIR}/bin/ossec-makelists > /dev/null 2>&1
}

### MAIN HERE ###

case "$1" in
start)
    testconfig
    lock
    start
    unlock
    ;;
stop)
    lock
    stopa
    unlock
    ;;
restart)
    testconfig
    lock
    stopa
    buildCDB
    start
    unlock
    ;;
reload)
    DAEMONS=$(echo $DAEMONS | sed 's/ossec-execd//')
    lock
    stopa
    start
    unlock
    ;;
status)
    lock
    status
    unlock
    ;;
help)
    help
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
*)
    help
esac

exit $RETVAL
