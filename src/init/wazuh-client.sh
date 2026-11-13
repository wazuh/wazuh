#!/bin/sh

# Copyright (C) Wazuh Inc.
# wazuh-control        This shell script takes care of starting
#                      or stopping Wazuh
# Author: Daniel B. Cid <daniel.cid@gmail.com>

LOCAL=`dirname $0`;
cd ${LOCAL}
PWD=`pwd`
DIR=`dirname $PWD`;

# Installation info
VERSION="v5.1.0"
REVISION="alpha0"
TYPE="agent"

###  Do not modify below here ###
AUTHOR="Wazuh Inc."
DAEMONS="wazuh-modulesd wazuh-logcollector wazuh-syscheckd wazuh-agentd wazuh-execd"

# Reverse order of daemons
SDAEMONS=$(echo $DAEMONS | awk '{ for (i=NF; i>1; i--) printf("%s ",$i); print $1; }')

# glibc >= 2.43 backs every aarch64 malloc arena with 2 MiB huge pages. Kept if already set:
# operator choice, or a reload launched by a daemon that inherited it.
case ":${GLIBC_TUNABLES}:" in
    *:glibc.malloc.hugetlb=*) ;;
    *) GLIBC_TUNABLES="glibc.malloc.hugetlb=0${GLIBC_TUNABLES:+:$GLIBC_TUNABLES}"; export GLIBC_TUNABLES ;;
esac

## Locking for the start/stop
LOCK="${DIR}/var/start-script-lock"
LOCK_PID="${LOCK}/pid"
# Held by the one run at a time that may replace a lock whose holder is gone.
RECLAIM="${LOCK}.reclaim"
RECLAIM_PID="${RECLAIM}/pid"

# Seconds the lock wait may take, and then again the whole start sequence once the lock is held
# (start_service() sets its deadline after lock()). Each is below the unit's TimeoutSec (45,
# templates/wazuh-agent.service), or systemd reports a timeout instead of the daemon that did not
# come up, but a start that first waits long for the lock can still run past it. The start's
# budget is cumulative: a per-daemon counter adds up past that limit.
MAX_ITERATION="40"

MAX_KILL_TRIES=30

# The unit that supervises the agent when systemd is the init system (templates/wazuh-agent.service),
# where systemd keeps its runtime state, and the cgroup membership of this very process.
SYSTEMD_UNIT="wazuh-agent.service"
SYSTEMD_RUNTIME_DIR="/run/systemd/system"
SELF_CGROUP="/proc/$$/cgroup"

# Seconds to wait for wazuh-agent.service to finish starting or reloading before handing it an
# action. Longer than a start can take: ExecStartPre and ExecStart each get the unit's TimeoutSec
# (45), after which systemd itself leaves those states.
SYSTEMD_SETTLE_TIMEOUT="95"

# Whether pid $1 runs daemon $2. The pid file of an agent that did not stop cleanly (a crash, a power
# loss) can name a pid that another process took since, for instance after a reboot: it must be
# neither stopped nor taken for that daemon. Matches the program's name, not its path, so a daemon
# started through a symlink to the installation still counts. -ww: ps cuts the line to an exported
# COLUMNS even when its output is not a terminal.
pid_runs_daemon()
{
    _prd_args=`ps -ww -p $1 -o args= 2>/dev/null` || return 1
    case "${_prd_args%% *}" in
        */$2|$2) return 0 ;;
    esac
    return 1
}

checkpid()
{
    for i in ${DAEMONS}; do
        for j in `cat ${DIR}/var/run/${i}-*.pid 2>/dev/null`; do
            if ! pid_runs_daemon $j $i; then
                echo "Deleting PID file '${DIR}/var/run/${i}-${j}.pid' not used..."
                rm ${DIR}/var/run/${i}-${j}.pid
            fi
        done
    done
}

# Writes this run's pid into the file $1 unless it is there already: of two runs that both believe they
# made its directory, only the one that writes the pid owns it. Readable by every user: on the manager,
# the API, which runs as another user, checks who holds the lock.
write_pid()
{
    ( umask 022; set -C; echo "$$" > "$1" ) > /dev/null 2>&1
}

# Creates the directory $1 and writes this run's pid in it: true only when this run owns it. The pid is
# read back: a run stalled between creating the pid file and writing it may have lost the directory to a
# run that reclaimed it meanwhile, and then wrote into a file that is gone.
take_dir()
{
    ( umask 022; mkdir "$1" ) > /dev/null 2>&1 && write_pid "$1/pid" && [ "$(cat "$1/pid" 2>/dev/null)" = "$$" ]
}

# True when the pid file $1 names no live process, or names none at all.
pid_gone()
{
    ! kill -0 $(cat "$1" 2>/dev/null) > /dev/null 2>&1
}

# True when this run holds the lock.
holds_lock()
{
    [ "$(cat ${LOCK_PID} 2>/dev/null)" = "$$" ]
}

# Replaces a lock whose holder is gone with this run's, unless another run took it meanwhile. Only the
# holder of ${RECLAIM} gets here, so one run at a time. A live run writes its pid right after creating
# the lock, so a pid-less lock gets that moment first.
replace_stale_lock()
{
    [ -s ${LOCK_PID} ] || sleep 1
    pid_gone ${LOCK_PID} && rm -rf ${LOCK} && take_dir ${LOCK}
}

# A ${RECLAIM} whose holder is gone, or that stays pid-less for several rounds in a row, was left by a
# run that died holding it: remove it, so that a later round can take it. One held by a live run stays.
clear_dead_reclaim()
{
    if [ -s ${RECLAIM_PID} ]; then
        reclaim_pidless=0
        if pid_gone ${RECLAIM_PID}; then
            rm -rf ${RECLAIM}
        fi
    elif [ -d ${RECLAIM} ]; then
        reclaim_pidless=`expr ${reclaim_pidless} + 1`
        if [ "${reclaim_pidless}" -gt 4 ]; then
            rm -rf ${RECLAIM}
            reclaim_pidless=0
        fi
    fi
}

# Takes ${RECLAIM} and, holding it, replaces a stale lock: true when this run now holds the lock.
reclaim_lock()
{
    if ! take_dir ${RECLAIM}; then
        clear_dead_reclaim
        return 1
    fi
    reclaim_pidless=0
    replace_stale_lock
    reclaimed=$?
    rm -rf ${RECLAIM}
    return ${reclaimed}
}

# Waits up to MAX_ITERATION one-second rounds for the lock, reclaiming one whose holder is gone: a dead
# pid is stale right away. A lock with no pid yet may be mid-acquisition, so only several consecutive
# pid-less rounds make it stale. False when the lock is still held at the end.
wait_for_lock()
{
    i=0
    pidless=0
    reclaim_pidless=0
    until take_dir ${LOCK}; do
        sleep 1
        i=`expr $i + 1`
        if [ -s ${LOCK_PID} ]; then
            pidless=0
        elif [ -d ${LOCK} ]; then
            pidless=`expr ${pidless} + 1`
        fi
        if pid_gone ${LOCK_PID} && { [ -s ${LOCK_PID} ] || [ "${pidless}" -gt 2 ]; }; then
            reclaim_lock && return 0
        fi
        if [ "$i" = "${MAX_ITERATION}" ]; then
            return 1
        fi
    done
}

# Releases the lock if this run holds it: a run refused before it took the lock must not remove the
# lock of the run that did.
unlock()
{
    if holds_lock; then
        rm -rf ${LOCK}
    fi
}

lock()
{
    if ! wait_for_lock; then
        echo "ERROR: Another instance is locking this process."
        echo "If you are sure that no other instance is running, please remove ${LOCK}"
        exit 1
    fi
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
            exit 1;
        fi
    done
}

# Check folders
check_folders()
{
    SOCKETS_FOLDER="../queue/sockets"

    if [ ! -d $SOCKETS_FOLDER ]
    then
        if rm -rf $SOCKETS_FOLDER && mkdir -p $SOCKETS_FOLDER && chown wazuh:wazuh $SOCKETS_FOLDER && chmod 770 $SOCKETS_FOLDER
        then
            echo "WARNING: missing folder 'queue/sockets'. Restored back."
        else
            echo "ERROR: missing folder 'queue/sockets', and could not restore back."
            exit 1
        fi
    fi
}

# Check if the system uses systemd
is_systemd() {
    [ -d "${SYSTEMD_RUNTIME_DIR}" ]
}

# Whether this call has to go through wazuh-agent.service: systemd runs this installation's agent
# and the call is not one of the unit's own Exec lines (see systemd_redirect).
systemd_supervises_call()
{
    [ "X${WAZUH_CONTROL_SKIP_SYSTEMD}" = "X1" ] && return 1
    is_systemd || return 1
    command -v systemctl > /dev/null 2>&1 || return 1
    [ -r "${SELF_CGROUP}" ] || return 1
    unit_runs_this_installation || return 1
    ! called_by_unit_exec_line
}

# Whether the unit's PIDFile= is this installation's, compared through their real directories so
# that a symlinked installation path or a trailing slash still match.
unit_runs_this_installation()
{
    _ur_pidfile=$(systemctl show -p PIDFile "${SYSTEMD_UNIT}" 2>/dev/null | sed -n 's/^PIDFile=//p')
    case "${_ur_pidfile}" in
        */wazuh-agentd.pid) ;;
        *) return 1 ;;
    esac
    _ur_unit_run=$(cd "$(dirname "${_ur_pidfile}")" 2>/dev/null && pwd -P)
    [ -n "${_ur_unit_run}" ] || return 1
    [ "X${_ur_unit_run}" = "X$(cd "${DIR}/var/run" 2>/dev/null && pwd -P)" ]
}

# Whether systemd runs this call for one of the unit's Exec lines: it sits in the unit's cgroup and
# its pid, or its parent's, is the unit's ControlPID.
called_by_unit_exec_line()
{
    grep -Eq '/wazuh-agent\.service(/|$)' "${SELF_CGROUP}" || return 1
    _cu_control_pid=$(systemctl show -p ControlPID "${SYSTEMD_UNIT}" 2>/dev/null | sed -n 's/^ControlPID=//p')
    case "${_cu_control_pid}" in
        "$$"|"${PPID}") return 0 ;;
    esac
    return 1
}

# Waits up to SYSTEMD_SETTLE_TIMEOUT seconds while the unit is starting or reloading, and leaves
# the state it ends in in UNIT_STATE.
wait_for_unit_to_settle()
{
    UNIT_STATE=$(systemctl is-active "${SYSTEMD_UNIT}" 2>/dev/null)
    case "${UNIT_STATE}" in
        activating|reloading) ;;
        *) return ;;
    esac
    echo "${SYSTEMD_UNIT} is ${UNIT_STATE}: waiting for it to finish."
    _ws_deadline=`expr \`date +%s\` + ${SYSTEMD_SETTLE_TIMEOUT}`
    while [ "`date +%s`" -lt "${_ws_deadline}" ]; do
        sleep 1
        UNIT_STATE=$(systemctl is-active "${SYSTEMD_UNIT}" 2>/dev/null)
        case "${UNIT_STATE}" in
            activating|reloading) ;;
            *) return ;;
        esac
    done
}

# Run by start with the lock held. Between the unit's ExecStartPre, which releases the lock, and its
# ExecStart, which takes it, a start here would bring the daemons up outside the unit: ExecStart
# would find them running, systemd would refuse the PID file and ExecStopPost would stop the agent.
# So while the unit is starting, this releases the lock, waits for the unit and takes the lock
# again. Checked with the lock held, a start the unit begins afterwards waits for the lock in
# ExecStartPre, which then stops what this run starts and lets ExecStart bring it up inside.
wait_for_unit_start()
{
    systemd_supervises_call || return
    [ "$(systemctl is-active "${SYSTEMD_UNIT}" 2>/dev/null)" = "activating" ] || return
    unlock
    wait_for_unit_to_settle
    lock
}

# Hands stop, restart and reload to systemctl while systemd supervises the agent, and returns
# otherwise. Run outside systemd, they take the daemons away from the unit: it tracks
# wazuh-agentd through PIDFile=, so when this script stops it systemd runs ExecStop, which waits
# for this script's lock and then stops the daemons this same restart has just brought up, and
# the agent ends up stopped right after "Completed.". Through systemctl the unit runs them with
# its own ExecStop, ExecStart and ExecReload, which call this script again from inside the unit.
#
# Those calls from systemd's own ExecStartPre, ExecStart, ExecStop, ExecStopPost and ExecReload
# must stay here: systemctl would queue a job behind the one running them and wait until the unit
# times out. The unit's ControlPID is the process systemd started for the line it is running (this
# script, or a shell that runs it), so a call from inside the unit's cgroup is one of them when its
# pid or its parent's is the ControlPID. Any other call from there comes from something the
# daemons launched, such as an upgrade's installer, and is handled like a call from outside.
#
# Every other call waits while the unit is starting or reloading. A stop or restart job issued
# then cuts the start or reload short: systemd skips ExecStop (it runs it only after a
# successful start) and, with KillMode=process, only signals wazuh-agentd, so the other daemons
# are left to ExecStopPost. A reload issued during a start is folded into it and returns 0
# without reloading anything. Once the unit is active, all three are handed over. While it is
# stopping, stop and restart are handed over too, and run after that stop.
#
# Left to this script:
# - a unit that runs another installation of the agent, whose PIDFile= is not in this one.
# - a process whose cgroup can't be read, since it can't tell where it runs.
# - a unit that is not running: the agent was started with this script, or it is stopped. A
#   reload then starts the daemons that are down, as it does without systemd.
# - a reload while the unit is stopping, which waits for this script's lock like before.
# - a unit still starting or reloading after SYSTEMD_SETTLE_TIMEOUT seconds.
# - start, which is never handed over: on a running unit systemctl start does nothing, while this
#   script still brings up a daemon that is down. It only waits while the unit is starting (see
#   wait_for_unit_start).
# WAZUH_CONTROL_SKIP_SYSTEMD=1 keeps every action in this script.
systemd_redirect()
{
    systemd_supervises_call || return
    wait_for_unit_to_settle
    case "${UNIT_STATE}" in
        active) ;;
        deactivating) [ "$1" = "reload" ] && return ;;
        *) return ;;
    esac

    # systemctl restart stops the daemons before ExecStart tests the configuration, so a broken
    # one would leave the agent stopped. Test it first, as a restart run here does.
    if [ "$1" = "restart" ]; then
        testconfig
    fi

    echo "${SYSTEMD_UNIT} is managed by systemd: running 'systemctl $1 ${SYSTEMD_UNIT}'."
    exec systemctl "$1" "${SYSTEMD_UNIT}"
}

# Add daemons to agentd cgroup if systemd is used in legacy systems
add_to_cgroup()
{
    AGENTD_PID=$(head -n 1 ${DIR}/var/run/wazuh-agentd-*.pid 2>/dev/null)
    CGROUP_PATH="/sys/fs/cgroup/systemd/system.slice/wazuh-agent.service/cgroup.procs"

    # Check if cgroup path exists
    if [ ! -f "$CGROUP_PATH" ]; then
        echo "Warning: cgroup path does not exist: $CGROUP_PATH" >&2
    else
        for pidfile in ${DIR}/var/run/wazuh-*.pid; do
            [ -f "$pidfile" ] || continue
            pid=$(cat "$pidfile" 2>/dev/null)
            [ -z "$pid" ] && continue
            [ "$pid" = "$AGENTD_PID" ] && continue

            # Try to write to cgroup, capture any errors
            if ! echo "$pid" >> "$CGROUP_PATH" 2>/dev/null; then
                echo "Warning: Failed to add PID $pid to cgroup ($(basename "$pidfile"))" >&2
            fi
        done
    fi
}

# The agent's log, which start_service() reads to tell why a daemon did not start. logs/ belongs
# to the agent's user: the log is read only as a regular file, and never waited on for more than a
# few seconds where timeout(1) exists (a FIFO swapped in). Only the last 256 KiB of what is read are
# searched, so a device swapped in cannot grow grep's line without bound, and NUL bytes (left by a
# truncation) are dropped first, since GNU grep would otherwise take it for binary and print nothing.
OSSEC_LOG="${DIR}/logs/ossec.log"
LOG_START=0
if command -v timeout > /dev/null 2>&1; then
    LOG_TIMEOUT="timeout 5"
else
    LOG_TIMEOUT=""
fi

# Size of the agent's log in bytes, or nothing when it is not a regular file.
log_size()
{
    if [ -f "${OSSEC_LOG}" ] && [ ! -L "${OSSEC_LOG}" ]; then
        ${LOG_TIMEOUT} wc -c "${OSSEC_LOG}" 2>/dev/null | awk '{ print $1 }'
    fi
}

# What daemon $1 or one of its components ("wazuh-agentd:https-client") logged at level(s) $2 (an
# ERE, e.g. 'ERROR|CRITICAL') since this start began, with control characters removed. Matches the
# debug format too ("wazuh-agentd[123] agentd.c:176 at AgentdStart(): CRITICAL:"), and lines with
# bytes that are not valid in the locale (LC_ALL=C). A log that shrank since then was rotated: it is
# read from its start. $3, when given, is the log's size, already measured by the caller.
log_since()
{
    [ "${LOG_START}" != "none" ] || return 0
    _ls_size=$3
    [ -n "${_ls_size}" ] || _ls_size=`log_size`
    [ -n "${_ls_size}" ] || return 0
    _ls_from=${LOG_START}
    if [ "${_ls_size}" -lt "${_ls_from}" ]; then
        _ls_from=0
    fi
    ${LOG_TIMEOUT} tail -c +`expr ${_ls_from} + 1` "${OSSEC_LOG}" 2>/dev/null | tail -c 262144 \
        | tr -d '\000' \
        | LC_ALL=C grep -E "^[0-9/]+ [0-9:]+ $1(:[^ []+)?(\[[0-9]+\] [^ ]+ at [^ ]+\(\))?: ($2):" 2>/dev/null \
        | LC_ALL=C tr -d '\001-\010\013-\037\177'
}

# Start function
start_service()
{
    echo "Starting Wazuh $VERSION..."
    checkpid;

    # Delete all files in temporary folder
    TO_DELETE="$DIR/tmp/*"
    rm -rf $TO_DELETE

    start_deadline=`expr \`date +%s\` + ${MAX_ITERATION}`
    STARTED=""

    # A daemon that exits after going to the background (wazuh-agentd refusing an enrollment
    # token, say) leaves no PID file, which looks the same as one still starting. What it logged
    # since here tells them apart, and is the reason this start shows when one does not come up.
    # A log that does not exist yet is all this start's. One that exists but cannot be measured
    # (not a regular file) is not read at all: there would be no telling this start's lines from
    # older ones, and an old CRITICAL must not fail a start.
    LOG_START=`log_size`
    if [ -z "${LOG_START}" ]; then
        if [ -e "${OSSEC_LOG}" ] || [ -L "${OSSEC_LOG}" ]; then
            LOG_START="none"
        else
            LOG_START=0
        fi
    fi

    # We actually start them now.
    for i in ${SDAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
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
                log_seen=""
                while [ $failed = false ]; do
                    pstatus ${i};
                    if [ $? = 1 ]; then
                        break;
                    fi
                    # A CRITICAL is only logged on the way to exit, the daemon's own or one of its
                    # components': the daemon is gone. The log is searched again only once its size changed.
                    log_now=`log_size`
                    if [ -n "${log_now}" ] && [ "${log_now}" != "${log_seen}" ]; then
                        log_seen=${log_now}
                        if [ -n "`log_since ${i} CRITICAL ${log_now}`" ]; then
                            failed=true
                            break;
                        fi
                    fi
                    sleep 1;
                    if [ "`date +%s`" -ge "${start_deadline}" ]; then
                        failed=true
                    fi
                done
            fi
            if [ $failed = true ]; then
                echo "${i} did not start; see ${OSSEC_LOG} for the reason";
                log_since ${i} 'ERROR|CRITICAL' | tail -n 5
                # Stop what this start brought up, so the agent is not left half started; daemons
                # that were already running stay, though under the unit its ExecStopPost then stops
                # them too. A reload keeps wazuh-agentd up, so it stops nothing.
                # The deadline already took most of the unit's TimeoutSec: one second per daemon.
                if [ -z "${RELOADING}" ]; then
                    DAEMONS="${STARTED} ${i}"
                    MAX_KILL_TRIES=2
                    stop_service;
                fi
                unlock;
                exit 1;
            fi
            echo "Started ${i}..."
            STARTED="${STARTED} ${i}"
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
    _pstatus_quiet=${2:-""}

    # pfile must be set
    if [ "X${pfile}" = "X" ]; then
        return 0;
    fi

    ls ${DIR}/var/run/${pfile}-*.pid > /dev/null 2>&1
    if [ $? = 0 ]; then
        for pid in `cat ${DIR}/var/run/${pfile}-*.pid 2>/dev/null`; do
            if ! pid_runs_daemon ${pid} ${pfile}; then
                if [ "X${_pstatus_quiet}" = "X" ]; then
                    echo "${pfile}: Process ${pid} not used by Wazuh, removing .."
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
            echo "Killing ${i}... ";
            pid=`cat ${DIR}/var/run/${i}-*.pid`
            kill $pid
        else
            echo "${i} not running...";
        fi
    done

    # Second pass: wait for all processes that are still alive
    for i in ${DAEMONS}; do
        pstatus ${i} "quiet";
        if [ $? = 1 ]; then
            pid=`cat ${DIR}/var/run/${i}-*.pid`

            if ! wait_pid $pid
            then
                # Check the process again, not its file: a PID taken over by another program
                # while waiting must not be killed.
                if pid_runs_daemon $pid $i; then
                    echo "Process ${i} couldn't be terminated. It will be killed.";
                    kill -9 $pid
                fi
            fi
        fi

        rm -f ${DIR}/var/run/${i}-*.pid
        if [ "$i" = "wazuh-agentd" ]; then
            # Fixed-path PID file, written only for wazuh-agent.service's PIDFile=.
            rm -f ${DIR}/var/run/wazuh-agentd.pid
        fi
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
    wait_for_unit_start
    start_service
    unlock
    ;;
stop)
    systemd_redirect stop
    lock
    stop_service
    unlock
    ;;
restart)
    systemd_redirect restart
    restart_service
    ;;
reload)
    systemd_redirect reload
    RELOADING=1
    DAEMONS=$(echo $DAEMONS | sed 's/wazuh-agentd//')
    if is_systemd; then
        SYSTEMD_VERSION=$(systemctl --version | awk 'NR==1 {print $2}')
        if [ "$SYSTEMD_VERSION" -le 237 ]; then
            LEGACY_SYSTEMD_VERSION=1
        fi
    fi
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
