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
VERSION="v4.12.0"
REVISION="alpha0"
TYPE="server"

###  Do not modify below here ###

# Getting additional processes
ls -la ${PLIST} > /dev/null 2>&1
if [ $? = 0 ]; then
. ${PLIST};
fi

AUTHOR="Wazuh Inc."
USE_JSON=false
DAEMONS="wazuh-clusterd wazuh-modulesd wazuh-monitord wazuh-logcollector wazuh-remoted wazuh-syscheckd wazuh-analysisd wazuh-maild wazuh-execd wazuh-db wazuh-authd wazuh-agentlessd wazuh-integratord wazuh-dbd wazuh-csyslogd wazuh-apid"
OP_DAEMONS="wazuh-clusterd wazuh-maild wazuh-agentlessd wazuh-integratord wazuh-dbd wazuh-csyslogd"
DEPRECATED_DAEMONS="ossec-authd"

# Reverse order of daemons
SDAEMONS=$(echo $DAEMONS | awk '{ for (i=NF; i>1; i--) printf("%s ",$i); print $1; }')
OP_SDAEMONS=$(echo $OP_DAEMONS | awk '{ for (i=NF; i>1; i--) printf("%s ",$i); print $1; }')

## Locking for the start/stop
LOCK="${DIR}/var/start-script-lock"
LOCK_PID="${LOCK}/pid"

# This number should be more than enough (even if it is
# started multiple times together). It will try for up
# to 10 attempts (or 10 seconds) to execute.
MAX_ITERATION="60"

MAX_KILL_TRIES=600


checkpid()
{
    for i in ${CDAEMONS}; do
        for j in `cat ${DIR}/var/run/${i}-*.pid 2>/dev/null`; do
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
    echo "Usage: $0 [-j] {start|stop|restart|status|enable|disable|info [-v -r -t]}";
    echo ""
    echo "    -j    Use JSON output."
    exit 1;
}

AUTHD_MSG="This option is deprecated because Authd is now enabled by default."
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
    elif [ "X$2" = "Xauth" ]; then
        echo "$AUTHD_MSG"
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
        echo "Usage: $0 disable debug]"
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
        ${DIR}/bin/${i} -t ${DEBUG_CLI};
        if [ $? != 0 ]; then
            if [ $USE_JSON = true ]; then
                echo -n '{"error":20,"message":"'${i}': Configuration error."}'
            else
                echo "${i}: Configuration error. Exiting"
            fi
            if [ ! -f ${DIR}/var/run/.restart ]; then
                touch ${DIR}/var/run/${i}.failed
            fi
            rm -f ${DIR}/var/run/*.start
            rm -f ${DIR}/var/run/.restart
            unlock;
            exit 1;
        fi
    done
}

# Start function
start_service()
{

    if [ $USE_JSON = false ]; then
        echo "Starting Wazuh $VERSION..."
    fi

    TEST=$(${DIR}/bin/wazuh-logtest-legacy -t  2>&1 | grep "ERROR")
    if [ ! -z "$TEST" ]; then
        if [ $USE_JSON = true ]; then
            echo -n '{"error":21,"message":"OSSEC analysisd: Testing rules failed. Configuration error."}'
        else
            echo "OSSEC analysisd: Testing rules failed. Configuration error. Exiting."
        fi
        touch ${DIR}/var/run/wazuh-analysisd.failed
        exit 1;
    fi

    checkpid;

    # Delete all files in temporary folder
    TO_DELETE="$DIR/tmp"
    find $TO_DELETE -mindepth 1 -not -path "$TO_DELETE/vd_*_vd_*.tar" -not -path "$TO_DELETE/vd_*_vd_*.tar.xz" -delete

    # Stop deprecated daemons that could keep alive on updates
    for i in ${DEPRECATED_DAEMONS}; do
        ls ${DIR}/var/run/${i}-*.pid > /dev/null 2>&1
        if [ $? = 0 ]; then
            pid=`cat ${DIR}/var/run/${i}-*.pid`
            kill $pid
            rm -f ${DIR}/var/run/${i}-${pid}.pid
        fi
    done

    # We actually start them now.
    first=true
    if [ $USE_JSON = true ]; then
        echo -n '{"error":0,"data":['
    fi
    for i in ${SDAEMONS}; do
        ## If wazuh-maild is disabled, don't try to start it.
        if [ X"$i" = "Xwazuh-maild" ]; then
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
        ## If wazuh-authd is disabled, don't try to start it.
        if [ X"$i" = "Xwazuh-authd" ]; then
             start_config="$(grep -n "<auth>" ${DIR}/etc/ossec.conf | cut -d':' -f 1)"
             end_config="$(grep -n "</auth>" ${DIR}/etc/ossec.conf | cut -d':' -f 1)"
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
            ## Create starting flag
            failed=false
            rm -f ${DIR}/var/run/${i}.failed
            touch ${DIR}/var/run/${i}.start
            if [ $USE_JSON = true ]; then
                ${DIR}/bin/${i} ${DEBUG_CLI} > /dev/null 2>&1;
            else
                ${DIR}/bin/${i} ${DEBUG_CLI};
            fi
            if [ $? != 0 ]; then
                failed=true
            else
                is_optional ${i};
                if [ $? = 0 ]; then
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
            fi
            if [ $failed = true ]; then
                if [ $USE_JSON = true ]; then
                    echo -n '{"daemon":"'${i}'","status":"error"}'
                else
                    echo "${i} did not start correctly.";
                fi
                rm -f ${DIR}/var/run/${i}.start
                touch ${DIR}/var/run/${i}.failed
                rm -f ${DIR}/var/run/*.start
                rm -f ${DIR}/var/run/.restart
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

    if [ $USE_JSON = true ]; then
        echo -n ']}'
    else
        echo "Completed."
    fi
    rm -f ${DIR}/var/run/*.start
}

is_optional()
{
    daemon=$1
    for op in ${OP_SDAEMONS}; do
        # If the daemon is optional, don't check if it is running in background.
        if [ X"$op" = X"$daemon" ]; then
            return 1;
        fi
    done
    return 0;
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
                if [ $USE_JSON = false ]; then
                    echo "${pfile}: Process ${pid} not used by Wazuh, removing..."
                fi
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

            pid=`cat ${DIR}/var/run/${i}-*.pid`
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
                    echo "Process ${i} couldn't be terminated. It will be killed.";
                    kill -9 $pid
                fi
            fi
        else
            if [ $USE_JSON = true ]; then
                echo -n '{"daemon":"'${i}'","status":"stopped"}'
            else
                echo "${i} not running...";
            fi
        fi
        rm -f ${DIR}/var/run/${i}-*.pid
    done

    if [ $USE_JSON = true ]; then
        echo -n ']}'
    else
        echo "Wazuh $VERSION Stopped"
    fi
}

info()
{
    if [ "X${1}" = "X" ]; then
        if [ $USE_JSON = true ]; then
            echo -n '{"error":0,"data":['
            echo -n '{"WAZUH_VERSION":"'${VERSION}'"},'
            echo -n '{"WAZUH_REVISION":"'${REVISION}'"},'
            echo -n '{"WAZUH_TYPE":"'${TYPE}'"}'
            echo -n ']}'
        else
            echo "WAZUH_VERSION=\"${VERSION}\""
            echo "WAZUH_REVISION=\"${REVISION}\""
            echo "WAZUH_TYPE=\"${TYPE}\""
        fi
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
    touch ${DIR}/var/run/.restart
    testconfig
    lock
    if [ $USE_JSON = true ]; then
        stop_service > /dev/null 2>&1
    else
        stop_service
    fi
    start_service
    rm -f ${DIR}/var/run/.restart
    unlock
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
    enable $action $arg;
    unlock
    ;;
disable)
    lock
    disable $action $arg;
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
