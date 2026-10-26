#!/bin/sh

# Copyright (C) Wazuh Inc.
# wazuh-manager-control        This shell script takes care of starting
#                      or stopping Wazuh
# Author: Daniel B. Cid <daniel.cid@gmail.com>

# Getting where we are installed
LOCAL=`dirname $0`;
cd ${LOCAL}
PWD=`pwd`
DIR=`dirname $PWD`;
PLIST=${DIR}/bin/.process_list;
# The configuration directory is fixed: a custom installation home moves the home only. Kept identical
# with CONF_DIR in src/init/shared.sh and WAZUH_MANAGER_CONF_DIR in defs.h.
CONF_DIR="/etc/wazuh-manager"
WAZUH_CONF="${WAZUH_CONF:-wazuh-manager.conf}"
# Reader of the manager configuration: validation and effective values (schema defaults applied).
MCONF="${DIR}/bin/wazuh-manager-conf -H ${DIR} -f ${CONF_DIR}/${WAZUH_CONF}"

# Installation info
VERSION="v5.0.1"
REVISION="alpha0"
TYPE="manager"

###  Do not modify below here ###

# Getting additional processes
if [ -f "${PLIST}" ]; then
. ${PLIST};
fi

AUTHOR="Wazuh Inc."
USE_JSON=false
DAEMONS="wazuh-manager-clusterd wazuh-manager-modulesd wazuh-manager-remoted wazuh-manager-analysisd wazuh-manager-db wazuh-manager-authd wazuh-manager-apid"

# The words of $1 in reverse order.
reverse_list()
{
    _reversed=""
    for _word in $1; do
        _reversed="${_word}${_reversed:+ ${_reversed}}"
    done
    echo "${_reversed}"
}

# Reverse order of daemons
SDAEMONS=$(reverse_list "${DAEMONS}")

## Locking for the start/stop
LOCK="${DIR}/var/start-script-lock"
LOCK_PID="${LOCK}/pid"

# Seconds the lock loop waits. Below the unit's TimeoutSec (45, which bounds stop only; start and
# reload both run under TimeoutStartSec=180 for the engine readiness wait, since systemd applies the
# start timeout to ExecReload, templates/wazuh-manager.service), or systemd reports a timeout instead
# of the real reason.
MAX_ITERATION="40"

MAX_KILL_TRIES=30

lock()
{
    i=0;
    unreachable=0;
    marker_busy=0;

    # Providing a lock.
    while [ 1 ]; do
        if mkdir ${LOCK} > /dev/null 2>&1; then
            # Lock acquired (setting the pid)
            echo "$$" > ${LOCK_PID}
            return;
        fi

        # Waiting 1 second before trying again
        sleep 1;
        i=`expr $i + 1`;
        pid=$(cat ${LOCK_PID} 2>/dev/null)

        # Only consecutive pid-less rounds may open the gate below. Neither
        # "$i" (a caller queued behind a live owner would inherit an open
        # gate the moment that owner is gone) nor a round spent on a dead
        # pid says anything about a lock that is still mid-acquisition.
        if [ -z "${pid}" ]; then
            unreachable=`expr ${unreachable} + 1`
        else
            unreachable=0
        fi

        # An empty pid (no pid file) fails kill -0 just like a dead one.
        kill -0 ${pid} >/dev/null 2>&1
        if [ "$?" != "0" ]; then
            # A dead pid is stale right away; a missing one may still be
            # mid-acquisition, so it needs a few consecutive rounds first.
            if [ -n "${pid}" ] || [ "${unreachable}" -gt 2 ]; then
                # mkdir on this marker is exclusive like ${LOCK}'s own, so
                # only one caller at a time may unlock and recreate ${LOCK}.
                if mkdir "${LOCK}.reclaim" > /dev/null 2>&1; then
                    marker_busy=0
                    # Another caller may have reclaimed ${LOCK} meanwhile.
                    rpid=$(cat ${LOCK_PID} 2>/dev/null)
                    kill -0 ${rpid} >/dev/null 2>&1
                    if [ ! $? = 0 ]; then
                        unlock;
                        if mkdir ${LOCK} > /dev/null 2>&1; then
                            echo "$$" > ${LOCK_PID}
                            rmdir "${LOCK}.reclaim" > /dev/null 2>&1
                            return;
                        fi
                    fi
                    rmdir "${LOCK}.reclaim" > /dev/null 2>&1
                else
                    # The marker is held only briefly; one still busy after
                    # several consecutive rounds was left by a dead caller.
                    marker_busy=`expr ${marker_busy} + 1`
                    if [ "${marker_busy}" -gt 4 ]; then
                        rmdir "${LOCK}.reclaim" > /dev/null 2>&1
                        marker_busy=0
                    fi
                fi
            fi
        fi

        # We tried MAX_ITERATION times to acquire the lock.
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
    echo "Usage: $0 [-j] {start|stop|restart|reload|status|enable|disable|info [-v -r -t]}";
    echo ""
    echo "    -j    Use JSON output."
    exit 1;
}

# Enables additional daemons
enable()
{
    if [ -z "$1" ]; then
        echo ""
        echo "Enable options: debug"
        echo "Usage: $0 enable debug"
        exit 1;
    fi

    if [ "$1" = "debug" ]; then
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
    if [ -z "$1" ]; then
        echo ""
        echo "Disable options: debug"
        echo "Usage: $0 disable debug]"
        exit 1;
    fi

    if [ "$1" = "debug" ]; then
        echo "DEBUG_CLI=\"\"" >> ${PLIST};
    else
        echo ""
        echo "Invalid disable option."
        echo ""
        echo "Disable options: debug"
        echo "Usage: $0 disable debug"
        exit 1;
    fi
}

get_node_type()
{
    ${MCONF} get cluster.node_type 2>/dev/null
}

status()
{
    RETVAL=0
    first=true

    node_type=$(get_node_type);

    if [ $USE_JSON = true ]; then
        echo -n '{"error":0,"data":['
    fi
    for i in ${DAEMONS}; do
        ## The API daemon only runs on the master node
        if [ "$i" = "wazuh-manager-apid" ] && [ "$node_type" != "master" ]; then
            continue
        fi

        ## Mirror start_service(): authd is not started when auth.disabled is true.
        if [ "$i" = "wazuh-manager-authd" ] && [ "$(${MCONF} get auth.disabled 2>/dev/null)" = "true" ]; then
            continue
        fi

        if [ $USE_JSON = true ] && [ $first = false ]; then
            echo -n ','
        else
            first=false
        fi
        pstatus ${i};
        if [ $? = 0 ]; then
            # The marker testconfig() leaves on a refused configuration, and the same one the
            # framework reads as 'failed'. Without it a rejected value is indistinguishable from a
            # daemon that was never started.
            if [ -f ${DIR}/var/run/${i}.failed ]; then
                if [ $USE_JSON = true ]; then
                    echo -n '{"daemon":"'${i}'","status":"failed"}'
                elif [ "`cat ${DIR}/var/run/${i}.failed 2>/dev/null`" = "refused" ]; then
                    echo "${i} refused its configuration..."
                else
                    echo "${i} failed to start..."
                fi
            elif [ $USE_JSON = true ]; then
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

# validateconfig [--skip-file-checks]: the whole configuration file (XML, schema, cross-field rules
# and, unless told to skip them, the files it references). It fails fast with the JSON pointer of the
# offending option before any daemon runs its own -t, and stays ahead of stop_service() on the
# restart path, so a configuration mistake is refused while the manager is still up rather than after
# it has been taken down.
#
# It runs twice. First with --skip-file-checks, ahead of checkcredentials(): the resolver reads the
# TLS file names from the configuration, which it cannot do from a file the validator refuses, and
# the operator is owed the validator's verdict on such a file, not a credentials one. Then whole, in
# testconfig(), once the credentials check has named whatever is wrong with the files it trusts.
validateconfig()
{
    # Each marker is a verdict from a previous run, and this run's verdict replaces them; this
    # function may exit before checkcredentials() or testconfig() clears them.
    rm -f ${DIR}/var/run/*.failed

    MCONF_VERDICT=$(${MCONF} "$@" validate 2>&1)
    if [ $? = 0 ]; then
        return 0
    fi
    echo "${MCONF_VERDICT}" >&2
    # With the fail-fast no daemon starts, so nothing else records the reason where operators (and
    # the integration tests) look for it: surface the verdict in the manager log too.
    echo "$(date '+%Y/%m/%d %H:%M:%S') wazuh-manager-control: ERROR: ${MCONF_VERDICT}" >> ${DIR}/logs/wazuh-manager.log 2>/dev/null
    if [ $USE_JSON = true ]; then
        echo -n '{"error":20,"message":"'${WAZUH_CONF}': Configuration error."}'
    else
        echo "${WAZUH_CONF}: Configuration error. Exiting"
    fi
    rm -f ${DIR}/var/run/*.start
    rm -f ${DIR}/var/run/.restart
    # Before lock() on both paths, like checkcredentials() and testconfig(): see the note there.
    unlock;
    exit 1;
}

# The credentials and certificates, checked right after the configuration file itself on the start
# and restart paths (validateconfig --skip-file-checks), before the files it names.
#
# Read-only: the resolver's --check tests every entry it trusts -- local.env, ca/, export/, certs/
# and every file in them, the indexer's export -- for ownership, type and mode, and validates what is
# already there (the .env syntax, supplied values, the CA, the server pairs, the indexer trust). It
# takes no lock, starts no subprocess but the configuration reader (wazuh-manager-conf dump, for the
# configured TLS file names) and reports as missing only what --prestart could not complete either
# (the CA, the bundle and the server pairs, created at --install only, and indexer files with nothing
# in the export to import): completing the rest is --prestart's job, and on the restart path a pair
# nobody can provide must refuse the restart before the daemons are stopped, not after.
# That is what lets it run ahead of testconfig() -- and so ahead of the stop on the restart path --
# where resolvecredentials() cannot (see below). It has to come before the file checks: testconfig()
# would otherwise stop the start on "(1244) file not found" for a certificate without ever naming the
# entry that caused it.
#
# Any non-zero answer refuses the start, including the resolver failing to run: a verdict we could
# not obtain is not a reason to start.
checkcredentials()
{
    # Each marker is a verdict from a previous run, and this run's verdict replaces them; testconfig()
    # clears them too, but this function may exit before it runs. Without this, a refusal here would
    # leave `status` reporting another run's "refused its configuration".
    rm -f ${DIR}/var/run/*.failed

    if [ ! -x ${DIR}/bin/wazuh-manager-resolve-credentials ]; then
        return 0
    fi

    # Captured and relayed on stderr, as in resolvecredentials(), so that `-j` keeps writing a single
    # JSON document to stdout. The resolver names the rule and the path, never a value.
    CHECK_VERDICT=$(${DIR}/bin/wazuh-manager-resolve-credentials --check -H ${DIR} 2>&1)
    if [ $? = 0 ]; then
        return 0
    fi
    if [ -n "${CHECK_VERDICT}" ]; then
        echo "${CHECK_VERDICT}" >&2
    fi
    # UNSAFE: an entry root may not trust (owner, type, mode, a link). INVALID: something in place
    # that is wrong (a bad local.env line, an expired or mismatched certificate). MISSING: something
    # --prestart could not provide either, reported as resolvecredentials() reports it. Anything else
    # (not run as root, an internal error) means the check itself could not run, which refuses the
    # start just the same but must not be reported as a verdict about the credentials.
    CHECK_ERROR=22
    case "${CHECK_VERDICT}" in
        *UNSAFE*)  CHECK_REASON="Unsafe credentials"; CHECK_LOG="unsafe credentials" ;;
        *INVALID*) CHECK_REASON="Invalid credentials"; CHECK_LOG="invalid credentials" ;;
        *MISSING*) CHECK_REASON="Unresolved credentials"; CHECK_LOG="unresolved credentials"; CHECK_ERROR=21 ;;
        *)         CHECK_REASON="Cannot check the credentials"; CHECK_LOG="cannot check the credentials" ;;
    esac
    echo "$(date '+%Y/%m/%d %H:%M:%S') wazuh-manager-control: ERROR: ${CHECK_LOG}" >> ${DIR}/logs/wazuh-manager.log 2>/dev/null
    if [ -n "${CHECK_VERDICT}" ]; then
        echo "${CHECK_VERDICT}" >> ${DIR}/logs/wazuh-manager.log 2>/dev/null
    fi
    if [ $USE_JSON = true ]; then
        echo -n '{"error":'"${CHECK_ERROR}"',"message":"'"${CHECK_REASON}"'."}'
    else
        echo "${CHECK_REASON}. Exiting"
    fi
    rm -f ${DIR}/var/run/*.start
    rm -f ${DIR}/var/run/.restart
    # Like testconfig(), this runs before lock() on both paths: unlock() is `rm -rf ${LOCK}`, so it
    # releases nothing of ours -- and, as there, it would also remove a lock another invocation holds.
    unlock;
    exit 1;
}

# Credential resolution, run immediately before the daemons and while we are still root.
#
# Deliberately NOT part of testconfig(), and deliberately not run while any daemon is up: the
# resolver asks the keystore whether the indexer credential is already stored, and that opens the
# `queue/keystore` RocksDB read-write. keystore_server answers the framework's KeystoreClient from
# the same database -- once per API request that reaches the indexer -- so a probe issued while the
# manager is running races it for RocksDB's directory lock. The loser does not merely fail: the
# wrapper treats an IOError as corruption and runs rocksdb::RepairDB() over a database another
# process has open. restart_service() therefore calls this AFTER stop_service(), and the start path
# calls it with nothing running.
#
# --prestart runs every --check test again, then completes what a start needs: the Server API
# passwords and rbac.db, the indexer password in the keystore, the indexer's CA and client pair
# imported from /etc/wazuh-indexer/export when it changed or was never imported. It never mints a CA
# or issues a server pair -- those happen once, at installation -- and validates the ones in place,
# so an operator who replaced them with their own PKI keeps them untouched.
#
# A warning (indexer material that only the clock refuses) does not refuse the start; it is copied to
# wazuh-manager.log. --check before it says nothing on success, so each warning is logged once.
#
# Unresolved credentials fail here rather than at the daemon's own -t: a missing indexer password or
# CA is not a configuration error and has no JSON pointer to report, and the resolver has already
# named what is missing and where to put it.
resolvecredentials()
{
    if [ ! -x ${DIR}/bin/wazuh-manager-resolve-credentials ]; then
        return 0
    fi

    # Belt and braces for the call ordering above, so that a future caller cannot reintroduce the
    # race by moving this. keystore_server lives inside modulesd and answers the framework's
    # KeystoreClient from the very database this step opens; pstatus returns 1 when it is up. If it
    # is, this is not a pre-start -- a `start` against a running manager, or a caller out of order --
    # and there is nothing to resolve, because whatever is running resolved it when it started.
    pstatus wazuh-manager-modulesd "quiet"
    if [ $? = 1 ]; then
        return 0
    fi

    # Captured rather than left on stdout, for the same reason testconfig() captures the
    # configuration validator's verdict: `wazuh-manager-control -j start` writes exactly one JSON
    # document to stdout, and the resolver's progress lines would be prepended to it and break every
    # parser. They go to stderr instead -- the journal keeps both streams, which is where someone
    # looks when a unit will not start. The resolver never prints a value, only key names, so
    # relaying it in full leaks nothing.
    CREDENTIALS_VERDICT=$(${DIR}/bin/wazuh-manager-resolve-credentials --prestart -H ${DIR} 2>&1)
    CREDENTIALS_STATUS=$?
    if [ -n "${CREDENTIALS_VERDICT}" ]; then
        echo "${CREDENTIALS_VERDICT}" >&2
    fi
    # A warning stops nothing (indexer material only the clock refuses: the connection fails until it is
    # renewed or the clock is right), so the start goes on; it still belongs in the log operators read, not
    # only in the journal. Shell builtins only: this script runs no grep.
    if [ ${CREDENTIALS_STATUS} = 0 ] && [ -n "${CREDENTIALS_VERDICT}" ]; then
        printf '%s\n' "${CREDENTIALS_VERDICT}" | while IFS= read -r line; do
            case "${line}" in
                "resolve-credentials: WARNING: "*)
                    echo "$(date '+%Y/%m/%d %H:%M:%S') wazuh-manager-control: WARNING: ${line#resolve-credentials: WARNING: }" >> ${DIR}/logs/wazuh-manager.log 2>/dev/null
                    ;;
            esac
        done
    fi
    if [ ${CREDENTIALS_STATUS} != 0 ]; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') wazuh-manager-control: ERROR: unresolved credentials" >> ${DIR}/logs/wazuh-manager.log 2>/dev/null
        # No daemon starts, so nothing else records which key was missing where operators (and the
        # integration tests) look for it.
        echo "${CREDENTIALS_VERDICT}" >> ${DIR}/logs/wazuh-manager.log 2>/dev/null
        if [ $USE_JSON = true ]; then
            echo -n '{"error":21,"message":"Unresolved credentials."}'
        else
            echo "Unresolved credentials. Exiting"
        fi
        rm -f ${DIR}/var/run/*.start
        rm -f ${DIR}/var/run/.restart
        # unlock() is `rm -rf ${LOCK}`, so calling it on the start path -- which has not taken the
        # lock yet -- is harmless, and on the restart path it releases the lock we are holding.
        unlock;
        exit 1;
    fi
}

testconfig()
{
    # Each marker is a verdict from a previous run and this one replaces all of them. Cleared
    # here, not in start_service(): this function exits 1 on the FIRST failure, so start_service()
    # may never run to clear a marker left by an earlier, unrelated one.
    rm -f ${DIR}/var/run/*.failed

    # The whole configuration file again, now with the files it references: the certificates and
    # keys checkcredentials() has already vouched for, and every other file the options name.
    validateconfig

    # Then each daemon checks what is not configuration (files, sockets, keys).
    for i in ${SDAEMONS}; do
        ${DIR}/bin/${i} -t ${DEBUG_CLI};
        if [ $? != 0 ]; then
            if [ $USE_JSON = true ]; then
                echo -n '{"error":20,"message":"'${i}': Configuration error."}'
            else
                echo "${i}: Configuration error. Exiting"
            fi
            # Unconditionally: the wipe at the top of this function already replaced the old
            # .restart guard's job, and keeping the guard here would leave a restart with a
            # refused configuration reporting plain "not running".
            echo "refused" > ${DIR}/var/run/${i}.failed
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

    ${DIR}/bin/wazuh-manager-analysisd ${DEBUG_CLI}

    while [ $ticks -lt $max_ticks ]; do
        for pidfile in ${DIR}/var/run/wazuh-manager-analysisd-*.pid; do
            if [ -f "$pidfile" ]; then
                pidfile="${pidfile##*-}"
                echo "${pidfile%.pid}"
                return 0
            fi
        done
        ticks=$((ticks + 1))
        sleep 0.1
    done

    return 1  # timeout
}

# Asks the engine API whether it answers, through the bundled interpreter (the package declares no
# HTTP client). Succeeds on any status below 400, as `curl --fail` did; the socket timeout keeps a
# hung engine from stalling the readiness loop below.
ENGINE_PROBE='import http.client, socket, sys
class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(sys.argv[1])
try:
    connection = UnixConnection("localhost", timeout=5)
    connection.request("GET", "/status")
    sys.exit(0 if connection.getresponse().status < 400 else 1)
except Exception:
    sys.exit(1)'

wait_for_wazuh_engine_ready()
{
    local attempts=0
    local max_attempts=120

    ENGINE_PID=$(get_wazuh_engine_pid)
    if [ $? -ne 0 ]; then
        echo "Failed to obtain PID for wazuh-manager-analysisd"
        return 1
    fi

    while [ $attempts -lt $max_attempts ]; do
        ${DIR}/framework/python/bin/python3 -I -c "${ENGINE_PROBE}" \
            ${DIR}/queue/sockets/engine-api-http.sock > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            return 0
        fi

        if ! kill -0 "$ENGINE_PID" 2>/dev/null; then
            echo "wazuh-manager-analysisd died during the readiness check."
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

    # Delete all files in temporary folder. rm -rf does not follow a link it removes.
    for TO_DELETE in "$DIR"/tmp/* "$DIR"/tmp/.[!.]* "$DIR"/tmp/..?*; do
        if [ -e "$TO_DELETE" ] || [ -L "$TO_DELETE" ]; then
            rm -rf -- "$TO_DELETE"
        fi
    done

    node_type=$(get_node_type);
    if [ -z $node_type ]; then
        echo "Invalid cluster configuration, check the ${CONF_DIR}/${WAZUH_CONF} file."
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
        if [ "$i" = "wazuh-manager-apid" ] && [ "$node_type" != "master" ]; then
            continue
        fi

        ## If wazuh-manager-authd is disabled (auth.disabled: true), don't try to start it.
        if [ "$i" = "wazuh-manager-authd" ]; then
             if [ "$(${MCONF} get auth.disabled 2>/dev/null)" = "true" ]; then
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
            touch ${DIR}/var/run/${i}.start

            if [ "$i" = "wazuh-manager-analysisd" ]; then
                wait_for_wazuh_engine_ready
            elif [ $USE_JSON = true ]; then
                ${DIR}/bin/${i} ${DEBUG_CLI} > /dev/null 2>&1;
            else
                ${DIR}/bin/${i} ${DEBUG_CLI};
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
                # Same marker the framework reads as 'failed'; the content tells status why.
                echo "start" > ${DIR}/var/run/${i}.failed
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
    _pstatus_quiet=${2:-""}
    # pfile must be set
    if [ -z "${pfile}" ]; then
        return 0;
    fi

    ls ${DIR}/var/run/${pfile}-*.pid > /dev/null 2>&1
    if [ $? = 0 ]; then
        for pid in `cat ${DIR}/var/run/${pfile}-*.pid 2>/dev/null`; do
            if [ ! -d "/proc/${pid}" ]; then
                if [ $USE_JSON = false ] && [ -z "${_pstatus_quiet}" ]; then
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

        pstatus ${i} "quiet";

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
    if [ -z "${1}" ]; then
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
    validateconfig --skip-file-checks
    checkcredentials
    testconfig
    lock
    if [ $USE_JSON = true ]; then
        stop_service > /dev/null 2>&1
    else
        stop_service
    fi
    # After the stop, never before it: see resolvecredentials(). Probing the keystore while
    # keystore_server is still answering requests races it for the RocksDB directory lock.
    resolvecredentials
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
    validateconfig --skip-file-checks
    checkcredentials
    testconfig
    resolvecredentials
    lock
    start_service
    unlock
    RETVAL=0
    ;;
stop)
    lock
    stop_service
    unlock
    RETVAL=0
    ;;
restart)
    restart_service
    RETVAL=0
    ;;
reload)
    # Everything except remoted, which keeps the agents connected across a reload.
    RELOAD_DAEMONS=""
    for i in ${DAEMONS}; do
        if [ "$i" != "wazuh-manager-remoted" ]; then
            RELOAD_DAEMONS="${RELOAD_DAEMONS:+${RELOAD_DAEMONS} }$i"
        fi
    done
    DAEMONS="${RELOAD_DAEMONS}"
    SDAEMONS=$(reverse_list "${DAEMONS}")
    restart_service
    RETVAL=0
    ;;
status)
    lock
    status
    unlock
    ;;
enable)
    lock
    enable "$arg";
    unlock
    RETVAL=0
    ;;
disable)
    lock
    disable "$arg";
    unlock
    RETVAL=0
    ;;
info)
    info $arg
    RETVAL=0
    ;;
help)
    help
    ;;
*)
    if [ -n "$action" ]; then
        echo "Invalid action: ${action}"
    fi
    help
esac

exit ${RETVAL:-0}
