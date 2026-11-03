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
if [ "$1" = "-t" ]; then
    [ -f "${dir}/badconf-${name}" ] && exit 1
    exit 0
fi
[ -f "${dir}/fail-${name}" ] && exit 1
sleep 300 > /dev/null 2>&1 &
echo $! > "${dir}/var/run/${name}-$!.pid"
exit 0
'

# Stands in for systemctl: logs each call to systemctl.log. is-active prints the state in
# unit-state (inactive by default); any other action exits with the status in systemctl-rc (0).
SYSTEMCTL_STUB='#!/bin/sh
dir=$(cd "$(dirname "$0")/.." && pwd)
echo "$*" >> "${dir}/systemctl.log"
if [ "$1" = "is-active" ]; then
    state=$(cat "${dir}/unit-state" 2>/dev/null || echo inactive)
    echo "${state}"
    [ "${state}" = "active" ]
    exit $?
fi
exit $(cat "${dir}/systemctl-rc" 2>/dev/null || echo 0)
'

# Builds a fresh tree at ${WORK}/<case>. The copy of wazuh-control looks for systemd and for its
# own cgroup inside the tree (run-systemd/ and cgroup, both absent here), never at the host's, so
# no case reaches a wazuh-agent.service the host may run.
new_tree() {

    local dir="${WORK}/$1" daemon

    mkdir -p "${dir}/bin" "${dir}/var/run" "${dir}/tmp" "${dir}/queue/sockets" "${dir}/stubbin"
    sed -e "s|^SYSTEMD_RUNTIME_DIR=.*|SYSTEMD_RUNTIME_DIR=\"${dir}/run-systemd\"|" \
        -e "s|^SELF_CGROUP=.*|SELF_CGROUP=\"${dir}/cgroup\"|" \
        "${TARGET}" > "${dir}/bin/wazuh-control"
    for daemon in ${DAEMONS}; do
        printf '%s' "${DAEMON_STUB}" > "${dir}/bin/${daemon}"
    done
    printf '%s' "${SYSTEMCTL_STUB}" > "${dir}/stubbin/systemctl"
    chmod +x "${dir}/bin/"* "${dir}/stubbin/systemctl"

}

# Turns the case's tree into a host where systemd runs wazuh-agent.service in state $2 and this
# process sits in cgroup $3.
systemd_host() {

    local dir="${WORK}/$1"

    mkdir -p "${dir}/run-systemd"
    echo "$2" > "${dir}/unit-state"
    printf '%s\n' "$3" > "${dir}/cgroup"

}

# Runs wazuh-control <action> in the case's tree, with the systemctl stub first in PATH; prints
# its exit status.
control() {

    PATH="${WORK}/$1/stubbin:${PATH}" "${WORK}/$1/bin/wazuh-control" "$2" > "${WORK}/$1/$2.out" 2>&1
    echo $?

}

# The systemctl calls of the case, one per line.
systemctl_calls() {

    cat "${WORK}/$1/systemctl.log" 2>/dev/null

}

# The pids the case's daemons run with, to tell whether wazuh-control restarted them.
pids() {

    cat "${WORK}/$1/var/run/"*-*.pid 2>/dev/null | sort | tr '\n' ' '

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

# The copy each case runs must have taken both paths from the tree, or the systemd cases below
# would prove nothing and the others could reach the host's systemd.
new_tree isolation
check "the test copy looks for systemd in the tree" "1" \
    "$(grep -c "^SYSTEMD_RUNTIME_DIR=\"${WORK}/isolation/run-systemd\"$" "${WORK}/isolation/bin/wazuh-control")"
check "the test copy reads its cgroup from the tree" "1" \
    "$(grep -c "^SELF_CGROUP=\"${WORK}/isolation/cgroup\"$" "${WORK}/isolation/bin/wazuh-control")"

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

# Run by hand while systemd runs wazuh-agent.service, stop, restart and reload go to systemctl,
# and wazuh-control touches no daemon itself.
SESSION_CGROUP="0::/user.slice/user-0.slice/session-1.scope"
UNIT_CGROUP="0::/system.slice/wazuh-agent.service"

for action in stop restart reload; do
    new_tree "sd_${action}"
    control "sd_${action}" start > /dev/null
    before="$(pids "sd_${action}")"
    systemd_host "sd_${action}" active "${SESSION_CGROUP}"
    check "${action} on an active unit returns systemctl's status" "0" "$(control "sd_${action}" "${action}")"
    check "${action} on an active unit goes to systemctl" \
        "is-active wazuh-agent.service
${action} wazuh-agent.service" "$(systemctl_calls "sd_${action}")"
    check "${action} on an active unit leaves the daemons to the unit" "${before}" "$(pids "sd_${action}")"
done

new_tree sd_activating
control sd_activating start > /dev/null
systemd_host sd_activating activating "${SESSION_CGROUP}"
control sd_activating restart > /dev/null
check "restart while the unit is starting goes to systemctl" \
    "is-active wazuh-agent.service
restart wazuh-agent.service" "$(systemctl_calls sd_activating)"

new_tree sd_reloading
control sd_reloading start > /dev/null
systemd_host sd_reloading reloading "${SESSION_CGROUP}"
control sd_reloading stop > /dev/null
check "stop while the unit is reloading goes to systemctl" \
    "is-active wazuh-agent.service
stop wazuh-agent.service" "$(systemctl_calls sd_reloading)"

new_tree sd_rc
control sd_rc start > /dev/null
systemd_host sd_rc active "${SESSION_CGROUP}"
echo 5 > "${WORK}/sd_rc/systemctl-rc"
check "a failed systemctl restart fails wazuh-control" "5" "$(control sd_rc restart)"

# systemctl restart would stop the daemons before ExecStart finds the error.
new_tree sd_badconf
control sd_badconf start > /dev/null
before="$(pids sd_badconf)"
systemd_host sd_badconf active "${SESSION_CGROUP}"
touch "${WORK}/sd_badconf/badconf-wazuh-syscheckd"
check "restart with a configuration error fails" "1" "$(control sd_badconf restart)"
check "restart with a configuration error does not reach systemctl" "is-active wazuh-agent.service" \
    "$(systemctl_calls sd_badconf)"
check "restart with a configuration error keeps the daemons" "${before}" "$(pids sd_badconf)"

new_tree sd_start
systemd_host sd_start active "${SESSION_CGROUP}"
check "start on an active unit runs in wazuh-control" "0" "$(control sd_start start)"
check "start on an active unit does not call systemctl" "" "$(systemctl_calls sd_start)"
check "start on an active unit brings the daemons up" "${DAEMONS}" "$(running sd_start)"

# systemd's own ExecStop and ExecStart, and whatever the daemons launch, run inside the unit's
# cgroup: there systemctl would wait for the job that is running this very call.
for cgroup in "${UNIT_CGROUP}" "1:name=systemd:/system.slice/wazuh-agent.service
0::/system.slice/wazuh-agent.service" "0::/system.slice/wazuh-agent.service/payload"; do
    new_tree sd_inside
    control sd_inside start > /dev/null
    before="$(pids sd_inside)"
    systemd_host sd_inside active "${cgroup}"
    check "restart inside the unit runs in wazuh-control (${cgroup##*:})" "0" "$(control sd_inside restart)"
    check "restart inside the unit does not call systemctl (${cgroup##*:})" "" "$(systemctl_calls sd_inside)"
    check "restart inside the unit restarts the daemons (${cgroup##*:})" "${DAEMONS}" "$(running sd_inside)"
    [ "${before}" != "$(pids sd_inside)" ]
    check "restart inside the unit gives the daemons new pids (${cgroup##*:})" "0" "$?"
    rm -rf "${WORK}/sd_inside"
done

# cgroup v1 (systemd 219 on RHEL 7 and Amazon Linux 2) lists one line per hierarchy. A root shell
# over SSH sits in its session scope there, and in the root of every other hierarchy.
new_tree sd_v1_session
control sd_v1_session start > /dev/null
systemd_host sd_v1_session active "11:cpuset:/
10:memory:/
4:cpuacct,cpu:/
3:pids:/user.slice
1:name=systemd:/user.slice/user-0.slice/session-1.scope"
control sd_v1_session restart > /dev/null
check "restart from a cgroup v1 session goes to systemctl" \
    "is-active wazuh-agent.service
restart wazuh-agent.service" "$(systemctl_calls sd_v1_session)"

# Another unit whose name ends like it is not the agent's.
new_tree sd_other_unit
control sd_other_unit start > /dev/null
systemd_host sd_other_unit active "0::/system.slice/my-wazuh-agent.service"
control sd_other_unit stop > /dev/null
check "a unit named like the agent's is not taken for it" \
    "is-active wazuh-agent.service
stop wazuh-agent.service" "$(systemctl_calls sd_other_unit)"

for state in inactive failed deactivating unknown; do
    new_tree "sd_${state}"
    control "sd_${state}" start > /dev/null
    systemd_host "sd_${state}" "${state}" "${SESSION_CGROUP}"
    check "stop on a ${state} unit runs in wazuh-control" "0" "$(control "sd_${state}" stop)"
    check "stop on a ${state} unit only asks systemctl the state" "is-active wazuh-agent.service" \
        "$(systemctl_calls "sd_${state}")"
    check "stop on a ${state} unit stops the daemons" "" "$(running "sd_${state}")"
done

new_tree sd_no_cgroup
control sd_no_cgroup start > /dev/null
systemd_host sd_no_cgroup active "${SESSION_CGROUP}"
rm -f "${WORK}/sd_no_cgroup/cgroup"
control sd_no_cgroup stop > /dev/null
check "stop with an unreadable cgroup does not call systemctl" "" "$(systemctl_calls sd_no_cgroup)"
check "stop with an unreadable cgroup stops the daemons" "" "$(running sd_no_cgroup)"

new_tree sd_no_systemd
control sd_no_systemd start > /dev/null
systemd_host sd_no_systemd active "${SESSION_CGROUP}"
rm -rf "${WORK}/sd_no_systemd/run-systemd"
control sd_no_systemd stop > /dev/null
check "stop without systemd does not call systemctl" "" "$(systemctl_calls sd_no_systemd)"
check "stop without systemd stops the daemons" "" "$(running sd_no_systemd)"

new_tree sd_skip
control sd_skip start > /dev/null
systemd_host sd_skip active "${SESSION_CGROUP}"
WAZUH_CONTROL_SKIP_SYSTEMD=1 control sd_skip stop > /dev/null
check "WAZUH_CONTROL_SKIP_SYSTEMD=1 keeps stop in wazuh-control" "" "$(systemctl_calls sd_skip)"
check "WAZUH_CONTROL_SKIP_SYSTEMD=1 stops the daemons" "" "$(running sd_skip)"

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
