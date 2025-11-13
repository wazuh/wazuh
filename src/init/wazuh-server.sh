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
VERSION="v5.0.0"
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
DAEMONS="wazuh-clusterd wazuh-modulesd wazuh-monitord wazuh-logcollector wazuh-remoted wazuh-syscheckd wazuh-analysisd wazuh-execd wazuh-db wazuh-authd wazuh-apid"
DEPRECATED_DAEMONS="ossec-authd"

# Reverse order of daemons
SDAEMONS=$(echo $DAEMONS | awk '{ for (i=NF; i>1; i--) printf("%s ",$i); print $1; }')

## Locking for the start/stop
LOCK="${DIR}/var/start-script-lock"
LOCK_PID="${LOCK}/pid"

# This number should be more than enough (even if it is
# started multiple times together). It will try for up
# to 10 attempts (or 10 seconds) to execute.
MAX_ITERATION="60"

MAX_KILL_TRIES=30


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

get_wazuh_engine_pid()
{
    local max_ticks=100
    local ticks=0
    local pidfile

    ${DIR}/bin/wazuh-analysisd

    while [ $ticks -lt $max_ticks ]; do
        pidfile=$(ls ${DIR}/var/run/wazuh-analysisd-*.pid 2>/dev/null | head -n1)
        if [ -n "$pidfile" ]; then
            echo "${pidfile##*-}" | sed 's/\.pid$//'
            return 0
        fi
        ticks=$((ticks + 1))
        sleep 0.1
    done

    return 1  # timeout
}

wait_for_wazuh_engine_ready()
{
    local attempts=0
    local max_attempts=240 # TODO Improve this value

    ENGINE_PID=$(get_wazuh_engine_pid)
    if [ $? -ne 0 ]; then
        echo "Failed to obtain PID for wazuh-analysisd"
        return 1
    fi

    while [ $attempts -lt $max_attempts ]; do
        curl --silent --unix-socket ${DIR}/queue/sockets/analysis \
            -X POST -H "Content-Type: application/json" \
            -d '{"name":"default"}' \
            http://localhost/router/route/get \
            > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            return 0
        fi

        if ! kill -0 "$ENGINE_PID" 2>/dev/null; then
            echo "wazuh-analysisd died during route check."
            return 1
        fi

        attempts=$((attempts + 1))
        sleep 1
    done

    echo "wazuh-analysisd did not respond correctly after $max_attempts attempts."
    kill $ENGINE_PID
    return 1
}

# Start function
start_service()
{

    if [ $USE_JSON = false ]; then
        echo "Starting Wazuh $VERSION..."
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

    node_type=$(grep '<node_type>' ${DIR}/etc/ossec.conf | sed 's/<node_type>\(.*\)<\/node_type>/\1/' | tr -d ' ');
    if [ -z $node_type ]; then
        echo "Invalid cluster configuration, check the $DIR/etc/ossec.conf file."
        unlock;
        exit 1;
    fi

    # We actually start them now.
    first=true
    if [ $USE_JSON = true ]; then
        echo -n '{"error":0,"data":['
    fi
    for i in ${SDAEMONS}; do
        ## Only start the API daemon on the master node
        if [ X"$i" = "Xwazuh-apid" ] && [ "$node_type" != "master" ]; then
            continue
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
                if [ "$i" = "wazuh-analysisd" ]; then
                    wait_for_wazuh_engine_ready
                else
                    ${DIR}/bin/${i} ${DEBUG_CLI};
                fi
            fi
            if [ $? != 0 ]; then
                failed=true
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
            sleep 1
            wp_counter=`expr $wp_counter + 1`
        fi
    done

    return 0
}

stop_service()
{
    checkpid;

    # First pass: send kill signal to all running daemons
    for i in ${DAEMONS}; do
        pstatus ${i};
        if [ $? = 1 ]; then
            if [ $USE_JSON != true ]
            then
                echo "Killing ${i}...";
            fi
            pid=`cat ${DIR}/var/run/${i}-*.pid`
            kill $pid
        else
            if [ $USE_JSON != true ]
            then
                echo "${i} not running...";
            fi
        fi
    done

    # Second pass: wait for all processes that are still alive
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
            pid=`cat ${DIR}/var/run/${i}-*.pid`

            if wait_pid $pid
            then
                if [ $USE_JSON = true ]; then
                    echo -n '{"daemon":"'${i}'","status":"stopped"}'
                fi
            else
                if [ $USE_JSON = true ]; then
                    echo -n '{"daemon":"'${i}'","status":"killed"}'
                else
                    echo "Process ${i} couldn't be terminated. It will be killed.";
                fi
                kill -9 $pid
            fi
        else
            if [ $USE_JSON = true ]; then
                echo -n '{"daemon":"'${i}'","status":"stopped"}'
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
