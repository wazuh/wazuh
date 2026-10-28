#!/bin/bash

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives the agent's wazuh-control (wazuh-client.sh) start, restart and reload against a throwaway
# install directory whose daemons are stubs: each one starts a background sleep and writes its pid
# file, as a daemon does once it is up, unless a fail-<daemon> file asks it to exit 1. Checks which
# daemons are left running when one of them does not start.
#
#   ./test_wazuh_control.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../wazuh-client.sh"

DAEMONS="wazuh-execd wazuh-agentd wazuh-syscheckd wazuh-logcollector wazuh-modulesd"

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
[ "$1" = "-t" ] && exit 0
[ -f "${dir}/fail-${name}" ] && exit 1
sleep 300 > /dev/null 2>&1 &
echo $! > "${dir}/var/run/${name}-$!.pid"
exit 0
'

# Builds a fresh tree at ${WORK}/<case>.
new_tree() {

    local dir="${WORK}/$1" daemon

    mkdir -p "${dir}/bin" "${dir}/var/run" "${dir}/tmp" "${dir}/queue/sockets"
    cp "${TARGET}" "${dir}/bin/wazuh-control"
    for daemon in ${DAEMONS}; do
        printf '%s' "${DAEMON_STUB}" > "${dir}/bin/${daemon}"
    done
    chmod +x "${dir}/bin/"*

}

# Runs wazuh-control <action> in the case's tree; prints its exit status.
control() {

    "${WORK}/$1/bin/wazuh-control" "$2" > "${WORK}/$1/$2.out" 2>&1
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

# A refused token bootstrap: wazuh-agentd does not come up after wazuh-execd did.
new_tree start_fail
touch "${WORK}/start_fail/fail-wazuh-agentd"
check "start fails when a daemon does not start" "1" "$(control start_fail start)"
check "the daemons that start brought up are stopped" "" "$(running start_fail)"

# Starting the daemons that are down must not take down the ones already running.
new_tree start_partial
control start_partial start > /dev/null
for pid in $(cat "${WORK}/start_partial/var/run/wazuh-logcollector"-*.pid "${WORK}/start_partial/var/run/wazuh-modulesd"-*.pid); do
    kill "${pid}"
done
touch "${WORK}/start_partial/fail-wazuh-modulesd"
check "start fails again on the daemon that is down" "1" "$(control start_partial start)"
check "only what that start brought up is stopped" "wazuh-execd wazuh-agentd wazuh-syscheckd" "$(running start_partial)"

new_tree restart_fail
control restart_fail start > /dev/null
touch "${WORK}/restart_fail/fail-wazuh-agentd"
check "restart fails when a daemon does not start" "1" "$(control restart_fail restart)"
check "a failed restart leaves no daemon running" "" "$(running restart_fail)"

# A reload keeps wazuh-agentd up: a failure must not leave it running alone.
new_tree reload_fail
control reload_fail start > /dev/null
touch "${WORK}/reload_fail/fail-wazuh-modulesd"
check "reload fails when a daemon does not start" "1" "$(control reload_fail reload)"
check "a failed reload stops nothing it started" "wazuh-execd wazuh-agentd wazuh-syscheckd wazuh-logcollector" "$(running reload_fail)"

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
