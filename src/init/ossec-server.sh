#!/bin/sh
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
DAEMONS="ossec-monitord ossec-logcollector ossec-remoted ossec-syscheckd ossec-analysisd ossec-maild ossec-execd wazuh-modulesd ${DB_DAEMON} ${CSYSLOG_DAEMON} ${AGENTLESS_DAEMON} ${INTEGRATOR_DAEMON}"
USE_JSON=false
INITCONF="/etc/ossec-init.conf"

[ -f ${INITCONF} ] && . ${INITCONF}  || echo "ERROR: No such file ${INITCONF}"

## Locking for the start/stop
LOCK="${DIR}/var/start-script-lock"
LOCK_PID="${LOCK}/pid"

# This number should be more than enough (even if it is
# started multiple times together). It will try for up
# to 10 attempts (or 10 seconds) to execute.
MAX_ITERATION="10"

checkpid()
{
    CDAEMONS="${DAEMONS} ossec-authd"

    for i in ${CDAEMONS}; do
        for j in `cat ${DIR}/var/run/${i}*.pid 2>/dev/null`; do
            ps -p $j >/dev/null 2>&1
            if [ ! $? = 0 ]; then
                if [ $USE_JSON = false ]; then
                    echo "Deleting PID file '${DIR}/var/run/${i}-${j}.pid' not used..."
                fi
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

unlock()
{
    rm -rf ${LOCK}
}

help()
{
    # Help message
    echo ""
    echo "Usage: $0 [-j] {start|stop|restart|status|enable|disable}";
    echo ""
    echo "    -j    Use JSON output."
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
        echo "Usage: $0 disable [database|client-syslog|agentless|debug|integrator]"
        exit 1;
    fi

    if [ "X$2" = "Xdatabase" ]; then
        echo "DB_DAEMON=\"\"" >> ${PLIST};
    elif [ "X$2" = "Xclient-syslog" ]; then
        echo "CSYSLOG_DAEMON=\"\"" >> ${PLIST};
    elif [ "X$2" = "Xagentless" ]; then
        echo "AGENTLESS_DAEMON=\"\"" >> ${PLIST};
    elif [ "X$2" = "Xintegrator" ]; then
        echo "INTEGRATOR_DAEMON=\"\"" >> ${PLIST};
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
}

status()
{
    RETVAL=0
    first=true

    lock;
    checkpid;
    unlock;

    if [ $USE_JSON = true ]; then
        echo -n '{"error":0,"data":['
    fi
    for i in ${DAEMONS}; do
        if [ $USE_JSON = true ] && [ $first = false ]; then
            echo -n ','
        else
            first=false
        fi
        pstatus ${i};
        if [ $? = 0 ]; then
            if [ $USE_JSON = true ]; then
                echo -n '{"daemon":"'${i}'","status":"stopped"}'
            else
                echo "${i} not running..."
            fi
            RETVAL=1
        else
            if [ $USE_JSON = true ]; then
                echo -n '{"daemon":"'${i}'","status":"running"}'
            else
                echo "${i} is running..."
            fi
        fi
    done
    if [ $USE_JSON = true ]; then
        echo -n ']}'
    fi
    exit $RETVAL
}

testconfig()
{
    # We first loop to check the config.
    for i in ${SDAEMONS}; do
        ${DIR}/bin/${i} -t ${DEBUG_CLI};
        if [ $? != 0 ]; then
            if [ $USE_JSON = true ]; then
                echo -n '{"error":20,"message":"'${i}': Configuration error."}'
            else
                echo "${i}: Configuration error. Exiting"
            fi
            unlock;
            exit 1;
        fi
    done
}

# Start function
start()
{
    SDAEMONS="${DB_DAEMON} ${CSYSLOG_DAEMON} ${AGENTLESS_DAEMON} ${INTEGRATOR_DAEMON} wazuh-modulesd ossec-maild ossec-execd ossec-analysisd ossec-logcollector ossec-remoted ossec-syscheckd ossec-monitord"

    if [ $USE_JSON = false ]; then
        echo "Starting $NAME $VERSION (maintained by $AUTHOR)..."
    fi
    ${DIR}/bin/ossec-logtest -t > /dev/null 2>&1;
    if [ ! $? = 0 ]; then
        if [ $USE_JSON = true ]; then
            echo -n '{"error":21,"message":"OSSEC analysisd: Testing rules failed. Configuration error."}'
        else
            echo "OSSEC analysisd: Testing rules failed. Configuration error. Exiting."
        fi
        exit 1;
    fi
    lock;
    checkpid;

    # We actually start them now.
    first=true
    if [ $USE_JSON = true ]; then
        echo -n '{"error":0,"data":['
    fi
    for i in ${SDAEMONS}; do
        if [ $USE_JSON = true ] && [ $first = false ]; then
            echo -n ','
        else
            first=false
        fi

        ## If ossec-maild is disabled, don't try to start it.
        if [ X"$i" = "Xossec-maild" ]; then
             grep "<email_notification>no<" ${DIR}/etc/ossec.conf >/dev/null 2>&1
             if [ $? = 0 ]; then
                 continue
             fi
        fi

        pstatus ${i};
        if [ $? = 0 ]; then
            if [ $USE_JSON = true ]; then
                ${DIR}/bin/${i} ${DEBUG_CLI} > /dev/null 2>&1;
            else
                ${DIR}/bin/${i} ${DEBUG_CLI};
            fi
            if [ $? != 0 ]; then
                if [ $USE_JSON = true ]; then
                    echo -n '{"daemon":"'${i}'","status":"error"}'
                else
                    echo "${i} did not start correctly.";
                fi
                unlock;
                exit 1;
            fi
            if [ $USE_JSON = true ]; then
                echo -n '{"daemon":"'${i}'","status":"running"}'
            else
                echo "Started ${i}..."
            fi
        else
            if [ $USE_JSON = true ]; then
                echo -n '{"daemon":"'${i}'","status":"running"}'
            else
                echo "${i} already running..."
            fi
        fi
    done

    # After we start we give 2 seconds for the daemons
    # to internally create their PID files.
    sleep 2;
    unlock;

    if [ $USE_JSON = true ]; then
        echo -n ']}'
    else
        echo "Completed."
    fi
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
                if [ $USE_JSON = false ]; then
                    echo "${pfile}: Process $j not used by ossec, removing .."
                fi
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

stopa()
{
    lock;
    checkpid;
    first=true
    if [ $USE_JSON = true ]; then
        echo -n '{"error":0,"data":['
    fi
    for i in ${DAEMONS}; do
        if [ $USE_JSON = true ] && [ $first = false ]; then
            echo -n ','
        else
            first=false
        fi
        pstatus ${i};
        if [ $? = 1 ]; then
            if [ $USE_JSON = true ]; then
                echo -n '{"daemon":"'${i}'","status":"killed"}'
            else
                echo "Killing ${i} .. ";
            fi
            kill `cat ${DIR}/var/run/${i}*.pid`;
        else
            if [ $USE_JSON = true ]; then
                echo -n '{"daemon":"'${i}'","status":"stopped"}'
            else
                echo "${i} not running ..";
            fi
        fi
        rm -f ${DIR}/var/run/${i}*.pid
    done

    unlock;
    if [ $USE_JSON = true ]; then
        echo -n ']}'
    else
        echo "$NAME $VERSION Stopped"
    fi
}

### MAIN HERE ###

if [ "$1" = "-j" ]; then
    USE_JSON=true
    action=$2
    arg=$3
else
    action=$1
    arg=$2
fi

case "$action" in
start)
    testconfig
    start
    ;;
stop)
    stopa
    ;;
restart)
    testconfig
    if [ $USE_JSON = true ]; then
        stopa > /dev/null 2>&1
    else
        stopa
    fi
    sleep 1;
    start
    ;;
reload)
    DAEMONS="ossec-monitord ossec-logcollector ossec-remoted ossec-syscheckd ossec-analysisd ossec-maild wazuh-modulesd ${DB_DAEMON} ${CSYSLOG_DAEMON} ${AGENTLESS_DAEMON} ${INTEGRATOR_DAEMON}"
    stopa
    start
    ;;
status)
    status
    ;;
help)
    help
    ;;
enable)
    enable $action $arg;
    ;;
disable)
    disable $action $arg;
    ;;
*)
    help
esac
