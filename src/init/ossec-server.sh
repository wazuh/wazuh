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

is_rhel_le_5() {
    RPM_RELEASE="/etc/redhat-release"

    # If SO is not RHEL, return (false)
    [ -r $RPM_RELEASE ] || return

    DIST_NAME=$(sed -rn 's/^(.*) release ([[:digit:]]+)[. ].*/\1/p' /etc/redhat-release)
    DIST_VER=$(sed -rn 's/^(.*) release ([[:digit:]]+)[. ].*/\2/p' /etc/redhat-release)

    [[ "$DIST_NAME" =~ ^CentOS ]] || [[ "$DIST_NAME" =~ ^"Red Hat" ]] && [ -n "$DIST_VER" ] && [ $DIST_VER -le 5 ]
}


AUTHOR="Wazuh Inc."
USE_JSON=false
INITCONF="/etc/ossec-init.conf"
DAEMONS="wazuh-modulesd ossec-monitord ossec-logcollector ossec-remoted ossec-syscheckd ossec-analysisd ossec-maild ossec-execd wazuh-db ossec-authd ${DB_DAEMON} ${CSYSLOG_DAEMON} ${AGENTLESS_DAEMON} ${INTEGRATOR_DAEMON}"

if ! is_rhel_le_5
then
    DAEMONS="wazuh-clusterd $DAEMONS"
fi

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

checkpid()
{
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
    echo "Usage: $0 [-j] {start|stop|restart|status|enable|disable}";
    echo ""
    echo "    -j    Use JSON output."
    exit 1;
}

AUTHD_MSG="This option is deprecated because Authd is now enabled by default. If you want to change it, modify the ossec.conf file."

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
    elif [ "X$2" = "Xauth" ]; then
        echo "$AUTHD_MSG"
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
    elif [ "X$2" = "Xauth" ]; then
        echo "$AUTHD_MSG"
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
    first=true

    checkpid;

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
}

testconfig()
{
    # We first loop to check the config.
    for i in ${SDAEMONS}; do
        if [ X"$i" = "Xwazuh-clusterd" ]; then
            continue
        fi
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
    incompatible=false

    if [ $USE_JSON = false ]; then
        echo "Starting $NAME $VERSION..."
    fi

    TEST=$(${DIR}/bin/ossec-logtest -t  2>&1 | grep "ERROR")
    if [ ! -z "$TEST" ]; then
        if [ $USE_JSON = true ]; then
            echo -n '{"error":21,"message":"OSSEC analysisd: Testing rules failed. Configuration error."}'
        else
            echo "OSSEC analysisd: Testing rules failed. Configuration error. Exiting."
        fi
        exit 1;
    fi

    if is_rhel_le_5
    then
        if [ $USE_JSON = true ]; then
            incompatible=true
        else
            echo "Cluster daemon is incompatible with CentOS 5 and RHEL 5... Skipping wazuh-clusterd."
        fi
    fi

    checkpid;

    # Delete all files in temporary folder
    TO_DELETE="$DIR/tmp/*"
    rm -rf $TO_DELETE

    # We actually start them now.
    first=true
    if [ $USE_JSON = true ]; then
        echo -n '{"error":0,"data":['
    fi
    for i in ${SDAEMONS}; do
        ## If ossec-maild is disabled, don't try to start it.
        if [ X"$i" = "Xossec-maild" ]; then
             grep "<email_notification>no<" ${DIR}/etc/ossec.conf >/dev/null 2>&1
             if [ $? = 0 ]; then
                 continue
             fi
        fi
        ## If wazuh-clusterd is disabled, don't try to start it.
        if [ X"$i" = "Xwazuh-clusterd" ]; then
             start_config="$(grep -n "<cluster>" ${DIR}/etc/ossec.conf | cut -d':' -f 1)"
             end_config="$(grep -n "</cluster>" ${DIR}/etc/ossec.conf | cut -d':' -f 1)"
             if [ -n "${start_config}" ] && [ -n "${end_config}" ]; then
                sed -n "${start_config},${end_config}p" ${DIR}/etc/ossec.conf | grep "<disabled>yes" >/dev/null 2>&1
                if [ $? = 0 ]; then
                    continue
                fi
             else
                continue
             fi
        fi
        if [ $USE_JSON = true ] && [ $first = false ]; then
            echo -n ','
        else
            first=false
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
    if $incompatible
    then
        echo -n '{"daemon":"wazuh-clusterd","status":"incompatible"}'
    fi
    # After we start we give 2 seconds for the daemons
    # to internally create their PID files.
    sleep 2;

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
                    echo "${pfile}: Process $j not used by ossec, removing..."
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
            if [ $USE_JSON != true ]
            then
                echo "Killing ${i}...";
            fi

            pid=`cat ${DIR}/var/run/${i}*.pid`
            kill $pid

            if wait_pid $pid
            then
                if [ $USE_JSON = true ]; then
                    echo -n '{"daemon":"'${i}'","status":"killed"}'
                fi
            else
                if [ $USE_JSON = true ]; then
                    echo -n '{"daemon":"'${i}'","status":"failed to kill"}'
                else
                    echo "Process ${i} couldn't be killed.";
                fi
            fi
        else
            if [ $USE_JSON = true ]; then
                echo -n '{"daemon":"'${i}'","status":"stopped"}'
            else
                echo "${i} not running...";
            fi
        fi
        rm -f ${DIR}/var/run/${i}*.pid
    done

    if [ $USE_JSON = true ]; then
        echo -n ']}'
    else
        echo "$NAME $VERSION Stopped"
    fi
}

buildCDB()
{
    ${DIR}/bin/ossec-makelists > /dev/null 2>&1
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
    if [ $USE_JSON = true ]; then
        stopa > /dev/null 2>&1
    else
        stopa
    fi
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
    enable $action $arg;
    unlock
    ;;
disable)
    lock
    disable $action $arg;
    unlock
    ;;
*)
    help
esac

exit $RETVAL
