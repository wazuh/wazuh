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
VERSION="v4.14.12"
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

MAX_KILL_TRIES=30

# Succeed when process $2 is daemon $1.
# comm is truncated on some systems (15 characters on Linux, 14 on HP-UX) and
# is a full path on others, so compare the base name as a prefix of the daemon
# name, with at least 14 characters or all of it.
is_daemon_process()
{
    idp_comm=`UNIX95= ps -p $2 -o comm= 2>/dev/null | sed 's/^ *//; s/ *$//'`
    idp_comm=${idp_comm##*/}
    idp_min=${#1}
    [ "${idp_min}" -gt 14 ] && idp_min=14
    case "$1" in
        "${idp_comm}"*)
            [ -n "${idp_comm}" ] && [ "${#idp_comm}" -ge "${idp_min}" ] && return 0
            ;;
    esac
    return 1
}

# Print, one per line, the PIDs of the running instances of daemon $1.
# A PID is used only when its file is named <daemon>-<pid>.pid, holds exactly
# that PID (as the daemons write it) and the process is that daemon. Any other
# file is stale and is removed.
daemon_pids()
{
    dp_name=$1
    for dp_file in ${DIR}/var/run/${dp_name}-*.pid; do
        [ -f "${dp_file}" ] || [ -L "${dp_file}" ] || continue

        dp_pid=${dp_file##*/${dp_name}-}
        dp_pid=${dp_pid%.pid}
        case "${dp_pid}" in
            ''|*[!0-9]*|0*|1|???????????*) dp_pid="" ;;
        esac
        if [ -n "${dp_pid}" ] && [ ! -L "${dp_file}" ]; then
            # Daemons create the file and write the PID right after, so an
            # empty file may still be in progress: neither use nor remove it.
            [ -f "${dp_file}" ] && [ ! -s "${dp_file}" ] && continue
            dp_content=`head -n 1 "${dp_file}" 2>/dev/null`
            [ "${dp_content}" = "${dp_pid}" ] || dp_pid=""
        else
            dp_pid=""
        fi
        if [ -z "${dp_pid}" ]; then
            echo "Ignoring PID file '${dp_file}': not a valid ${dp_name} PID file, removing .." >&2
            rm -f "${dp_file}"
            continue
        fi

        if ! ps -p ${dp_pid} > /dev/null 2>&1; then
            echo "Deleting PID file '${dp_file}' not used..." >&2
            rm -f "${dp_file}"
            continue
        fi

        if is_daemon_process ${dp_name} ${dp_pid}; then
            echo "${dp_pid}"
            continue
        fi
        echo "Ignoring PID file '${dp_file}': process ${dp_pid} is not ${dp_name}, removing .." >&2
        rm -f "${dp_file}"
    done
}

checkpid()
{
    for i in ${DAEMONS}; do
        daemon_pids ${i} > /dev/null
    done
}

# Print, one per line, the PIDs of the processes running daemon $1 from this installation, started as
# ${DIR}/bin/$1 without arguments, as start_service does. Only where the mount namespace tells this
# installation apart (Linux 3.8 and later): elsewhere, a Solaris global zone, an AIX system with WPARs or
# a host with containers would list the agents they run under the same path.
daemon_processes()
{
    dpr_mnt=`readlink /proc/$$/ns/mnt 2>/dev/null`
    [ -n "${dpr_mnt}" ] || return 0
    ps -A -o pid= -o args= 2>/dev/null | while read dpr_pid dpr_args; do
        [ "${dpr_args}" = "${DIR}/bin/$1" ] || continue
        [ "`readlink /proc/${dpr_pid}/ns/mnt 2>/dev/null`" = "${dpr_mnt}" ] && echo "${dpr_pid}"
    done
}

# Print the daemon_processes of $1 that no PID file names: a run killed after starting the daemon but
# before it wrote its PID file (for instance a reload cut short by a restart) leaves it untracked, and
# the next start would run a second instance.
untracked_pids()
{
    up_listed=" `daemon_pids $1 2>/dev/null | tr '\n' ' '` "
    for up_pid in `daemon_processes $1`; do
        case "${up_listed}" in
            *" ${up_pid} "*) ;;
            *) echo "${up_pid}" ;;
        esac
    done
}

# Stop the untracked instances of daemon $1 (see untracked_pids), so that starting it leaves only one.
stop_untracked()
{
    for su_pid in `untracked_pids $1`; do
        echo "Killing ${1} started without a PID file (${su_pid})..."
        kill ${su_pid} 2>/dev/null
        if ! wait_pid ${su_pid} && is_daemon_process $1 ${su_pid}; then
            kill -9 ${su_pid}
        fi
    done
}

# Succeed when the lock owner $1 is still running. The lock outlives a reboot, so a live process with its
# PID is not enough: it must be a wazuh-control (or older ossec-control) run other than this one. If ps
# cannot tell, assume it is.
lock_owner_running()
{
    [ "$1" = "$$" ] && return 1
    kill -0 $1 > /dev/null 2>&1 || return 1
    lor_args=`UNIX95= ps -p $1 -o args= 2>/dev/null`
    case " ${lor_args} " in
        "  "|*/wazuh-control\ *|*\ wazuh-control\ *|*/ossec-control\ *|*\ ossec-control\ *) return 0 ;;
    esac
    # Solaris and HP-UX cut the command line (80 and 64 characters), which can hide the script name
    case `uname -s` in
        SunOS|HP-UX) [ ${#lor_args} -ge 63 ] && return 0 ;;
    esac
    return 1
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
            if ! lock_owner_running ${pid}; then
                # The lock owner is gone.
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
    echo "Usage: $0 {start|stop|restart|reload|status|info [-v -r -t]}";
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

# Check if the system uses systemd
is_systemd() {
    [ -d /run/systemd/system ]
}

# Add daemons to agentd cgroup if systemd is used in legacy systems
add_to_cgroup()
{
    # ls lists unified/systemd last: they must be written last, or systemd leaves the scope cgroups behind
    CGROUP_PATHS=$(ls /sys/fs/cgroup/*/system.slice/wazuh-agent.service/cgroup.procs \
        /sys/fs/cgroup/system.slice/wazuh-agent.service/cgroup.procs 2>/dev/null)

    if [ -z "$CGROUP_PATHS" ]; then
        echo "Warning: cgroup path does not exist for wazuh-agent.service" >&2
    else
        for daemon in ${DAEMONS}; do
            for pid in $(daemon_pids ${daemon}); do
                for path in $CGROUP_PATHS; do
                    if ! echo "$pid" >> "$path" 2>/dev/null; then
                        echo "Warning: Failed to add PID $pid to $path (${daemon})" >&2
                    fi
                done
            done
        done
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
        ss_status=$?
        if [ ${ss_status} = 0 ]; then
            stop_untracked ${i}
            # An untracked instance may have written its PID file before it could be stopped
            pstatus ${i};
            ss_status=$?
        fi
        if [ ${ss_status} = 0 ]; then
            failed=false

            if [ ! -z "$LEGACY_SYSTEMD_VERSION" ]; then
                if command -v systemd-run >/dev/null 2>&1; then
                    # safe to use systemd-run
                    systemd-run --scope --slice=system.slice ${DIR}/bin/${i};
                else
                    echo "ERROR: systemd is in use but systemd-run is not available" >&2
                    exit 1
                fi
            else
                ${DIR}/bin/${i};
            fi

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

    if [ ! -z "$LEGACY_SYSTEMD_VERSION" ]; then
        add_to_cgroup
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

    if [ -n "`daemon_pids ${pfile}`" ]; then
        return 1;
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
        pids=`{ daemon_pids ${i}; daemon_processes ${i}; } | sort -u`
        if [ -n "${pids}" ]; then
            echo "Killing ${i}... ";
            for pid in ${pids}; do
                kill ${pid}
            done
        else
            echo "${i} not running...";
        fi
    done

    # Second pass: wait for all processes that are still alive
    for i in ${DAEMONS}; do
        for pid in `{ daemon_pids ${i}; daemon_processes ${i}; } | sort -u`; do
            if ! wait_pid ${pid}
            then
                # Check the process again, not its file: the daemon may have
                # removed its PID file and still be exiting, while a PID taken
                # over by another program must not be killed.
                if is_daemon_process ${i} ${pid}; then
                    echo "Process ${i} couldn't be terminated. It will be killed.";
                    kill -9 ${pid}
                fi
            fi
        done

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
    if is_systemd; then
        SYSTEMD_VERSION=$(systemctl --version | awk 'NR==1 {print $2}')
        if [ "$SYSTEMD_VERSION" -le 237 ]; then
            LEGACY_SYSTEMD_VERSION=1
        fi
    fi
    restart_service
    # Signal agentd (SIGUSR1) to reload (reconnects execd)
    for pid in `daemon_pids wazuh-agentd`; do
        kill -USR1 ${pid}
    done
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
