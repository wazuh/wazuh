#!/bin/sh

# Copyright (C) 2015, Wazuh Inc.
# wazuh-manager-control        This shell script takes care of starting
#                      or stopping ossec-hids
# Author: Daniel B. Cid <daniel.cid@gmail.com>

# Getting where we are installed
LOCAL=`dirname $0`;
cd ${LOCAL}
PWD=`pwd`
DIR=`dirname $PWD`;
PLIST=${DIR}/bin/.process_list;
WAZUH_CONF="${WAZUH_CONF:-wazuh-manager.conf}"

# Ensure the correct lib dir is used when agent/manager are co-hosted.
export LD_LIBRARY_PATH="${DIR}/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# Installation info
VERSION="v5.0.0"
REVISION="alpha0"
TYPE="server"
WAZUH_ENGINE_GROUP="${WAZUH_ENGINE_GROUP:-wazuh-manager}"
export WAZUH_ENGINE_GROUP

###  Do not modify below here ###

# Getting additional processes
ls -la ${PLIST} > /dev/null 2>&1
if [ $? = 0 ]; then
. ${PLIST};
fi

AUTHOR="Wazuh Inc."
USE_JSON=false
DAEMONS="wazuh-manager-clusterd wazuh-manager-modulesd wazuh-manager-monitord wazuh-manager-remoted wazuh-manager-analysisd wazuh-manager-db wazuh-manager-authd wazuh-manager-apid"
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
        daemon_name="$i"
        for j in `cat ${DIR}/var/run/${daemon_name}-*.pid 2>/dev/null`; do
            ps -p $j >/dev/null 2>&1
            if [ ! $? = 0 ]; then
                if [ $USE_JSON = false ]; then
                    echo "Deleting PID file '${DIR}/var/run/${daemon_name}-${j}.pid' not used..."
                fi
                rm ${DIR}/var/run/${daemon_name}-${j}.pid
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
        daemon_name="$i"
        ${DIR}/bin/${daemon_name} -t ${DEBUG_CLI};
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
# Check if the system uses systemd
is_systemd() {
    [ -d /run/systemd/system ]
}

# Add daemons to the manager cgroup if systemd is used in legacy systems.
add_to_cgroup()
{
    CGROUP_PATH="/sys/fs/cgroup/systemd/system.slice/wazuh-manager.service/cgroup.procs"

    # Check if cgroup path exists
    if [ ! -f "$CGROUP_PATH" ]; then
        echo "Warning: cgroup path does not exist: $CGROUP_PATH" >&2
    else
        for pidfile in ${DIR}/var/run/wazuh-manager-*.pid; do
            [ -f "$pidfile" ] || continue
            pid=$(cat "$pidfile" 2>/dev/null)
            [ -z "$pid" ] && continue

            # Try to write to cgroup, capture any errors
            if ! echo "$pid" >> "$CGROUP_PATH" 2>/dev/null; then
                echo "Warning: Failed to add PID $pid to cgroup ($(basename "$pidfile"))" >&2
            fi
        done
    fi
}

get_wazuh_engine_pid()
{
    local max_ticks=100
    local ticks=0
    local pidfile

    ${DIR}/bin/wazuh-manager-analysisd

    while [ $ticks -lt $max_ticks ]; do
        pidfile=$(ls ${DIR}/var/run/wazuh-manager-analysisd-*.pid 2>/dev/null | head -n1)
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
        echo "Failed to obtain PID for wazuh-manager-analysisd"
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
            echo "wazuh-manager-analysisd died during route check."
            return 1
        fi

        attempts=$((attempts + 1))
        sleep 1
    done

    echo "wazuh-manager-analysisd did not respond correctly after $max_attempts attempts."
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

    node_type=$(grep '<node_type>' ${DIR}/etc/${WAZUH_CONF} | sed 's/<node_type>\(.*\)<\/node_type>/\1/' | tr -d ' ');
    if [ -z $node_type ]; then
        echo "Invalid cluster configuration, check the $DIR/etc/${WAZUH_CONF} file."
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
        if [ X"$i" = "Xwazuh-manager-apid" ] && [ "$node_type" != "master" ]; then
            continue
        fi

        ## If wazuh-manager-authd is disabled, don't try to start it.
        if [ X"$i" = "Xwazuh-manager-authd" ]; then
             start_config="$(grep -n "<auth>" ${DIR}/etc/${WAZUH_CONF} | cut -d':' -f 1)"
             end_config="$(grep -n "</auth>" ${DIR}/etc/${WAZUH_CONF} | cut -d':' -f 1)"
             if [ -n "${start_config}" ] && [ -n "${end_config}" ]; then
                sed -n "${start_config},${end_config}p" ${DIR}/etc/${WAZUH_CONF} | grep "<disabled>yes" >/dev/null 2>&1
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
            daemon_name="$i"

            if [ ! -z "$LEGACY_SYSTEMD_VERSION" ]; then
                if command -v systemd-run >/dev/null 2>&1; then
                    # safe to use systemd-run
                    if [ $USE_JSON = true ]; then
                        systemd-run --scope --slice=system.slice ${DIR}/bin/${daemon_name} ${DEBUG_CLI} > /dev/null 2>&1
                    else
                        systemd-run --scope --slice=system.slice ${DIR}/bin/${daemon_name} ${DEBUG_CLI}
                    fi
                else
                    echo "ERROR: systemd is in use but systemd-run is not available" >&2
                    exit 1
                fi
            else
                if [ "$i" = "wazuh-manager-analysisd" ]; then
                    wait_for_wazuh_engine_ready
                elif [ $USE_JSON = true ]; then
                    ${DIR}/bin/${daemon_name} ${DEBUG_CLI} > /dev/null 2>&1;
                else
                    ${DIR}/bin/${daemon_name} ${DEBUG_CLI};
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

    # Add daemons to the manager cgroup if systemd is used.
    if [ ! -z "$LEGACY_SYSTEMD_VERSION" ]; then
        add_to_cgroup
    fi

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

    daemon_name="$pfile"
    ls ${DIR}/var/run/${daemon_name}-*.pid > /dev/null 2>&1
    if [ $? = 0 ]; then
        for pid in `cat ${DIR}/var/run/${daemon_name}-*.pid 2>/dev/null`; do
            ps -p ${pid} > /dev/null 2>&1
            if [ ! $? = 0 ]; then
                if [ $USE_JSON = false ]; then
                    echo "${pfile}: Process ${pid} not used by Wazuh, removing..."
                fi
                rm -f ${DIR}/var/run/${daemon_name}-${pid}.pid
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
        daemon_name="$i"
        pstatus ${i};
        if [ $? = 1 ]; then
            if [ $USE_JSON != true ]
            then
                echo "Killing ${i}...";
            fi
            pid=`cat ${DIR}/var/run/${daemon_name}-*.pid`
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
        daemon_name="$i"
        if [ $USE_JSON = true ] && [ $first = false ]; then
            echo -n ','
        else
            first=false
        fi

        pstatus ${i};

        if [ $? = 1 ]; then
            pid=`cat ${DIR}/var/run/${daemon_name}-*.pid`

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
        rm -f ${DIR}/var/run/${daemon_name}-*.pid
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
    if is_systemd; then
        SYSTEMD_VERSION=$(systemctl --version | awk 'NR==1 {print $2}')
        if [ "$SYSTEMD_VERSION" -le 237 ]; then
            LEGACY_SYSTEMD_VERSION=1
        fi
    fi
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
