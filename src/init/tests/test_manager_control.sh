#!/bin/bash

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives the manager's wazuh-manager-control (wazuh-server.sh) start, restart and reload against a
# throwaway install directory whose programs are stubs: each daemon starts a background sleep and
# writes its pid file, as a daemon does once it is up, unless a fail-<daemon> file asks it to exit 1;
# its -t passes unless a testfail-<daemon> file holds the output it prints on stderr before exiting 1;
# wazuh-manager-conf accepts the configuration (a master, authd enabled); the bundled interpreter
# answers the engine readiness probe; there is no credential resolver, so the credential steps are
# skipped. Checks which daemons are left running when one of them does not start.
#
#   ./test_manager_control.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../wazuh-server.sh"

# Start order (the reverse of DAEMONS in wazuh-server.sh).
DAEMONS="wazuh-manager-apid wazuh-manager-authd wazuh-manager-db wazuh-manager-analysisd wazuh-manager-remoted wazuh-manager-modulesd wazuh-manager-clusterd"

failures=0
checks=0

WORK="$(mktemp -d)"

# Stops every stub left running, by the pids its files hold.
cleanup() {

    local pid

    for pid in $(cat "${WORK}"/*/var/run/*.pid 2>/dev/null); do
        kill "${pid}" 2>/dev/null
    done
    rm -rf "${WORK}"

}
trap cleanup EXIT

DAEMON_STUB='#!/bin/sh
dir=$(cd "$(dirname "$0")/.." && pwd)
name=$(basename "$0")
if [ "$1" = "-t" ]; then
    [ -f "${dir}/testfail-${name}" ] || exit 0
    cat "${dir}/testfail-${name}" >&2
    exit 1
fi
[ -f "${dir}/fail-${name}" ] && exit 1
sleep 300 > /dev/null 2>&1 &
echo $! > "${dir}/var/run/${name}-$!.pid"
exit 0
'

# validate succeeds; get answers the two keys the control script reads.
CONF_STUB='#!/bin/sh
for arg in "$@"; do
    case "${last}" in
        get)
            case "${arg}" in
                cluster.node_type) echo master ;;
                auth.disabled) echo false ;;
            esac
            exit 0
            ;;
    esac
    last="${arg}"
done
exit 0
'

# Builds a fresh tree at ${WORK}/<case>.
new_tree() {

    local dir="${WORK}/$1" daemon

    mkdir -p "${dir}/bin" "${dir}/var/run" "${dir}/tmp" "${dir}/logs" "${dir}/queue/sockets" \
        "${dir}/framework/python/bin"
    cp "${TARGET}" "${dir}/bin/wazuh-manager-control"
    for daemon in ${DAEMONS}; do
        printf '%s' "${DAEMON_STUB}" > "${dir}/bin/${daemon}"
    done
    printf '%s' "${CONF_STUB}" > "${dir}/bin/wazuh-manager-conf"
    # The engine probe passes; service_write's calls (-I -c <code> <path> <append|replace>) run the host's
    # interpreter, so the markers and log lines it writes are the real snippet's.
    printf '#!/bin/sh\ncase "$5" in append|replace) exec python3 "$@" ;; esac\nexit 0\n' \
        > "${dir}/framework/python/bin/python3"
    chmod +x "${dir}/bin/"* "${dir}/framework/python/bin/python3"

}

# Runs wazuh-manager-control [-j] <action> in the case's tree; prints its exit status.
control() {

    local case="$1"
    shift
    "${WORK}/${case}/bin/wazuh-manager-control" "$@" > "${WORK}/${case}/out" 2> "${WORK}/${case}/err"
    echo $?

}

# The daemons of the case whose stub is still running, in start order.
running() {

    local daemon pid out=""

    for daemon in ${DAEMONS}; do
        for pid in $(cat "${WORK}/$1/var/run/${daemon}"-*.pid 2>/dev/null); do
            kill -0 "${pid}" 2>/dev/null && out="${out} ${daemon}"
        done
    done
    echo "${out# }"

}

# Stops the stubs of the given daemons, as a crash would.
crash() {

    local case="$1" daemon pid
    shift

    for daemon in "$@"; do
        for pid in $(cat "${WORK}/${case}/var/run/${daemon}"-*.pid 2>/dev/null); do
            kill "${pid}"
        done
    done

}

check() {

    local name="$1" expected="$2" actual="$3"

    checks=$(( checks + 1 ))
    if [ "${expected}" = "${actual}" ]; then
        echo "ok   - ${name}"
    else
        failures=$(( failures + 1 ))
        echo "FAIL - ${name}"
        echo "--- expected ---"
        echo "${expected}"
        echo "--- actual ---"
        echo "${actual}"
        echo "---"
    fi

}

new_tree start_ok
check "start brings every daemon up" "0" "$(control start_ok start)"
check "every daemon runs" "${DAEMONS}" "$(running start_ok)"

# remoted does not come up after apid, authd, wazuh-db and analysisd did.
new_tree start_fail
touch "${WORK}/start_fail/fail-wazuh-manager-remoted"
check "start fails when a daemon does not start" "1" "$(control start_fail start)"
check "the daemons that start brought up are stopped" "" "$(running start_fail)"
check "the daemon that did not start is marked" "start" "$(cat "${WORK}/start_fail/var/run/wazuh-manager-remoted.failed")"
check "the lock is released" "no" "$([ -d "${WORK}/start_fail/var/start-script-lock" ] && echo yes || echo no)"

# With -j, still one JSON document, closed at the failed daemon.
new_tree start_fail_json
touch "${WORK}/start_fail_json/fail-wazuh-manager-remoted"
check "start -j fails when a daemon does not start" "1" "$(control start_fail_json -j start)"
check "start -j prints one document" \
    '{"error":0,"data":[{"daemon":"wazuh-manager-apid","status":"running"},{"daemon":"wazuh-manager-authd","status":"running"},{"daemon":"wazuh-manager-db","status":"running"},{"daemon":"wazuh-manager-analysisd","status":"running"},{"daemon":"wazuh-manager-remoted","status":"error"}]}' \
    "$(cat "${WORK}/start_fail_json/out")"
check "start -j stops what it brought up" "" "$(running start_fail_json)"

# Starting the daemons that are down must not take down the ones already running.
new_tree start_partial
control start_partial start > /dev/null
crash start_partial wazuh-manager-modulesd wazuh-manager-clusterd
touch "${WORK}/start_partial/fail-wazuh-manager-clusterd"
check "start fails again on the daemon that is down" "1" "$(control start_partial start)"
check "only what that start brought up is stopped" \
    "wazuh-manager-apid wazuh-manager-authd wazuh-manager-db wazuh-manager-analysisd wazuh-manager-remoted" \
    "$(running start_partial)"

new_tree restart_fail
control restart_fail start > /dev/null
touch "${WORK}/restart_fail/fail-wazuh-manager-remoted"
check "restart fails when a daemon does not start" "1" "$(control restart_fail restart)"
check "a failed restart leaves no daemon running" "" "$(running restart_fail)"

# A reload keeps remoted up; it stops what it restarted.
new_tree reload_fail
control reload_fail start > /dev/null
touch "${WORK}/reload_fail/fail-wazuh-manager-modulesd"
check "reload fails when a daemon does not start" "1" "$(control reload_fail reload)"
check "a failed reload leaves only remoted running" "wazuh-manager-remoted" "$(running reload_fail)"

# A daemon's -t refuses the check that the service-control helper runs before an API restart: the
# refusal and its reason (the last line of the test's output) reach the manager log, since the
# helper's own output reaches no log.
new_tree check_refused
printf 'Error loading configuration: analysisd.orchestrator_threads out of range\n' \
    > "${WORK}/check_refused/testfail-wazuh-manager-analysisd"
check "check -j is refused by a daemon's -t" "1" "$(control check_refused -j check)"
check "check -j prints the refusal" '{"error":20,"message":"wazuh-manager-analysisd: Configuration error."}' \
    "$(cat "${WORK}/check_refused/out")"
check "the refusal and its reason are logged" \
    "wazuh-manager-control: ERROR: wazuh-manager-analysisd: Configuration error: Error loading configuration: analysisd.orchestrator_threads out of range" \
    "$(sed 's/^[^ ]* [^ ]* //' "${WORK}/check_refused/logs/wazuh-manager.log")"
check "check starts nothing" "" "$(running check_refused)"

# A C daemon prints dated log lines: the last one is the reason, without its date.
new_tree check_refused_c
printf '2026/10/29 10:00:00 wazuh-manager-modulesd: INFO: Started.\n2026/10/29 10:00:00 wazuh-manager-modulesd: CRITICAL: (2302): Invalid definition for vulnerability-detection.scan_workers: 99.\n\n' \
    > "${WORK}/check_refused_c/testfail-wazuh-manager-modulesd"
check "check is refused by modulesd's -t" "1" "$(control check_refused_c check)"
check "the last line of the test's output is logged, undated" \
    "wazuh-manager-control: ERROR: wazuh-manager-modulesd: Configuration error: wazuh-manager-modulesd: CRITICAL: (2302): Invalid definition for vulnerability-detection.scan_workers: 99." \
    "$(sed 's/^[^ ]* [^ ]* //' "${WORK}/check_refused_c/logs/wazuh-manager.log")"

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
