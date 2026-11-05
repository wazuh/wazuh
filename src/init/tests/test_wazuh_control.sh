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
# unit-state (inactive by default), and then moves to the one in unit-settle if there is one, as
# a unit that finishes starting or reloading; show -p PIDFile prints the path in unit-pidfile,
# show -p ControlPID the pid in control-pid (0), and --version a version line; any other action
# exits with the status in systemctl-rc (0).
SYSTEMCTL_STUB='#!/bin/sh
dir=$(cd "$(dirname "$0")/.." && pwd)
echo "$*" >> "${dir}/systemctl.log"
if [ "$1" = "show" ] && [ "$3" = "ControlPID" ]; then
    echo "ControlPID=$(cat "${dir}/control-pid" 2>/dev/null || echo 0)"
    exit 0
fi
if [ "$1" = "show" ]; then
    echo "PIDFile=$(cat "${dir}/unit-pidfile" 2>/dev/null)"
    exit 0
fi
if [ "$1" = "--version" ]; then
    echo "systemd 252 (252.39-1~deb12u2)"
    exit 0
fi
if [ "$1" = "is-active" ]; then
    state=$(cat "${dir}/unit-state" 2>/dev/null || echo inactive)
    echo "${state}"
    [ -f "${dir}/unit-settle" ] && mv "${dir}/unit-settle" "${dir}/unit-state"
    [ "${state}" = "active" ]
    exit $?
fi
exit $(cat "${dir}/systemctl-rc" 2>/dev/null || echo 0)
'

# Builds a fresh tree at ${WORK}/<case>. The copy of wazuh-control looks for systemd and for its
# own cgroup inside the tree (run-systemd/ and cgroup, both absent here), never at the host's, so
# no case reaches a wazuh-agent.service the host may run. It waits 3 s for a unit to settle.
new_tree() {

    local dir="${WORK}/$1" daemon

    mkdir -p "${dir}/bin" "${dir}/var/run" "${dir}/tmp" "${dir}/queue/sockets" "${dir}/stubbin"
    sed -e "s|^SYSTEMD_RUNTIME_DIR=.*|SYSTEMD_RUNTIME_DIR=\"${dir}/run-systemd\"|" \
        -e "s|^SELF_CGROUP=.*|SELF_CGROUP=\"${dir}/cgroup\"|" \
        -e "s|^SYSTEMD_SETTLE_TIMEOUT=.*|SYSTEMD_SETTLE_TIMEOUT=\"3\"|" \
        "${TARGET}" > "${dir}/bin/wazuh-control"
    for daemon in ${DAEMONS}; do
        printf '%s' "${DAEMON_STUB}" > "${dir}/bin/${daemon}"
    done
    printf '%s' "${SYSTEMCTL_STUB}" > "${dir}/stubbin/systemctl"
    chmod +x "${dir}/bin/"* "${dir}/stubbin/systemctl"

}

# Turns the case's tree into a host where systemd runs wazuh-agent.service in state $2 for this
# installation (its PIDFile= is the tree's) and this process sits in cgroup $3.
systemd_host() {

    local dir="${WORK}/$1"

    mkdir -p "${dir}/run-systemd"
    echo "$2" > "${dir}/unit-state"
    printf '%s\n' "$3" > "${dir}/cgroup"
    echo "${dir}/var/run/wazuh-agentd.pid" > "${dir}/unit-pidfile"

}

# Runs wazuh-control <action> in the case's tree, with the systemctl stub first in PATH; prints
# its exit status.
control() {

    PATH="${WORK}/$1/stubbin:${PATH}" "${WORK}/$1/bin/wazuh-control" "$2" > "${WORK}/$1/$2.out" 2>&1
    echo $?

}

# Like control, as systemd runs an ExecStart, ExecStop or ExecReload line: the unit's ControlPID
# is wazuh-control itself (self) or the shell that runs it (parent).
control_as_exec() {

    local tree="${WORK}/$1"

    if [ "$3" = "self" ]; then
        PATH="${tree}/stubbin:${PATH}" sh -c 'echo $$ > "$0/control-pid"; exec "$0/bin/wazuh-control" "$1"' \
            "${tree}" "$2" > "${tree}/$2.out" 2>&1
    else
        PATH="${tree}/stubbin:${PATH}" sh -c 'echo $$ > "$0/control-pid"; "$0/bin/wazuh-control" "$1"; exit $?' \
            "${tree}" "$2" > "${tree}/$2.out" 2>&1
    fi
    echo $?

}

# Stops the case's daemons and removes its tree, so no stub outlives the run.
drop_tree() {

    local pid

    for pid in $(cat "${WORK}/$1/var/run/"*.pid 2>/dev/null); do
        kill "${pid}" 2>/dev/null
    done
    rm -rf "${WORK:?}/$1"

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
check "the test copy waits 3 s for the unit to settle" "1" \
    "$(grep -c '^SYSTEMD_SETTLE_TIMEOUT="3"$' "${WORK}/isolation/bin/wazuh-control")"

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

# What wazuh-control asks systemctl before handing an action over: whose unit it is, then its state.
PROBE="show -p PIDFile wazuh-agent.service
is-active wazuh-agent.service"
# The same from inside the unit's cgroup, which first asks which process systemd is running for
# an ExecStart, ExecStop or ExecReload line.
PROBE_IN="show -p PIDFile wazuh-agent.service
show -p ControlPID wazuh-agent.service
is-active wazuh-agent.service"

for action in stop restart reload; do
    new_tree "sd_${action}"
    control "sd_${action}" start > /dev/null
    before="$(pids "sd_${action}")"
    systemd_host "sd_${action}" active "${SESSION_CGROUP}"
    check "${action} on an active unit returns systemctl's status" "0" "$(control "sd_${action}" "${action}")"
    check "${action} on an active unit goes to systemctl" \
        "${PROBE}
${action} wazuh-agent.service" "$(systemctl_calls "sd_${action}")"
    check "${action} on an active unit leaves the daemons to the unit" "${before}" "$(pids "sd_${action}")"
done

# While the unit is starting or reloading, a stop or restart job would skip ExecStop and leave
# every daemon but wazuh-agentd running, and a reload would be folded into the start: they wait
# for the unit to settle, and go to systemctl once it is active.
for state in activating reloading; do
    for action in stop restart reload; do
        new_tree "sd_wait_${state}_${action}"
        control "sd_wait_${state}_${action}" start > /dev/null
        before="$(pids "sd_wait_${state}_${action}")"
        systemd_host "sd_wait_${state}_${action}" "${state}" "${SESSION_CGROUP}"
        echo active > "${WORK}/sd_wait_${state}_${action}/unit-settle"
        check "${action} while the unit is ${state} returns systemctl's status once it is active" "0" \
            "$(control "sd_wait_${state}_${action}" "${action}")"
        check "${action} while the unit is ${state} waits for it, then goes to systemctl" \
            "${PROBE}
is-active wazuh-agent.service
${action} wazuh-agent.service" "$(systemctl_calls "sd_wait_${state}_${action}")"
        check "${action} while the unit is ${state} leaves the daemons to the unit" "${before}" \
            "$(pids "sd_wait_${state}_${action}")"
        drop_tree "sd_wait_${state}_${action}"
    done
done

# A start that fails leaves nothing for systemctl stop to do: the leftovers are stopped here.
new_tree sd_wait_failed
control sd_wait_failed start > /dev/null
systemd_host sd_wait_failed activating "${SESSION_CGROUP}"
echo failed > "${WORK}/sd_wait_failed/unit-settle"
check "stop on a start that fails runs in wazuh-control" "0" "$(control sd_wait_failed stop)"
check "stop on a start that fails does not reach systemctl stop" "${PROBE}
is-active wazuh-agent.service" "$(systemctl_calls sd_wait_failed)"
check "stop on a start that fails stops the daemons" "" "$(running sd_wait_failed)"

# A unit that does not settle in time is left to the script, as before systemd was involved.
new_tree sd_wait_timeout
control sd_wait_timeout start > /dev/null
systemd_host sd_wait_timeout activating "${SESSION_CGROUP}"
check "stop on a unit that stays activating runs in wazuh-control" "0" "$(control sd_wait_timeout stop)"
check "stop on a unit that stays activating does not reach systemctl stop" "0" \
    "$(grep -c '^stop' "${WORK}/sd_wait_timeout/systemctl.log")"
check "stop on a unit that stays activating stops the daemons" "" "$(running sd_wait_timeout)"

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
check "restart with a configuration error does not reach systemctl" "${PROBE}" \
    "$(systemctl_calls sd_badconf)"
check "restart with a configuration error keeps the daemons" "${before}" "$(pids sd_badconf)"

new_tree sd_start
systemd_host sd_start active "${SESSION_CGROUP}"
check "start on an active unit runs in wazuh-control" "0" "$(control sd_start start)"
check "start on an active unit does not call systemctl" "" "$(systemctl_calls sd_start)"
check "start on an active unit brings the daemons up" "${DAEMONS}" "$(running sd_start)"

# Inside the unit's cgroup, an active unit means the call comes from something the daemons
# launched (an upgrade's installer): it goes to systemctl.
for cgroup in "${UNIT_CGROUP}" "1:name=systemd:/system.slice/wazuh-agent.service
0::/system.slice/wazuh-agent.service" "0::/system.slice/wazuh-agent.service/payload"; do
    new_tree sd_inside
    control sd_inside start > /dev/null
    before="$(pids sd_inside)"
    systemd_host sd_inside active "${cgroup}"
    check "restart inside an active unit goes to systemctl (${cgroup##*:})" \
        "${PROBE_IN}
restart wazuh-agent.service" "$(control sd_inside restart > /dev/null; systemctl_calls sd_inside)"
    check "restart inside an active unit leaves the daemons to the unit (${cgroup##*:})" "${before}" \
        "$(pids sd_inside)"
    drop_tree sd_inside
done

# systemd's own ExecStart, ExecStop and ExecReload run inside the unit while it is activating,
# deactivating or reloading: there systemctl would wait for the job that is running this very
# call. The unit's ControlPID names that call, run directly or through a shell, and it stays in
# the script without waiting.
for who in self parent; do
    for state in activating deactivating reloading; do
        for action in restart stop; do
            new_tree sd_exec
            control sd_exec start > /dev/null
            systemd_host sd_exec "${state}" "${UNIT_CGROUP}"
            check "${action} from the Exec* line (${who}) while the unit is ${state} runs in wazuh-control" "0" \
                "$(control_as_exec sd_exec "${action}" "${who}")"
            check "${action} from the Exec* line (${who}) while the unit is ${state} does not ask its state" \
                "show -p PIDFile wazuh-agent.service
show -p ControlPID wazuh-agent.service" "$(systemctl_calls sd_exec)"
            if [ "${action}" = "restart" ]; then
                check "restart from the Exec* line (${who}) while the unit is ${state} restarts the daemons" \
                    "${DAEMONS}" "$(running sd_exec)"
            else
                check "stop from the Exec* line (${who}) while the unit is ${state} stops the daemons" "" \
                    "$(running sd_exec)"
            fi
            drop_tree sd_exec
        done
    done
done

# Anything else inside the unit's cgroup was launched by the daemons (an upgrade's installer):
# during a reload, its restart waits for the unit and goes to systemctl.
new_tree sd_exec_child
control sd_exec_child start > /dev/null
before="$(pids sd_exec_child)"
systemd_host sd_exec_child reloading "${UNIT_CGROUP}"
echo 1 > "${WORK}/sd_exec_child/control-pid"
echo active > "${WORK}/sd_exec_child/unit-settle"
control sd_exec_child restart > /dev/null
check "restart launched by a daemon during a reload waits for it and goes to systemctl" "${PROBE_IN}
is-active wazuh-agent.service
restart wazuh-agent.service" "$(systemctl_calls sd_exec_child)"
check "restart launched by a daemon during a reload leaves the daemons to the unit" "${before}" \
    "$(pids sd_exec_child)"
drop_tree sd_exec_child

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
    "${PROBE}
restart wazuh-agent.service" "$(systemctl_calls sd_v1_session)"

# Another unit whose name ends like it is not the agent's.
new_tree sd_other_unit
control sd_other_unit start > /dev/null
systemd_host sd_other_unit active "0::/system.slice/my-wazuh-agent.service"
control sd_other_unit stop > /dev/null
check "a unit named like the agent's is not taken for it" \
    "${PROBE}
stop wazuh-agent.service" "$(systemctl_calls sd_other_unit)"

for state in inactive failed unknown; do
    new_tree "sd_${state}"
    control "sd_${state}" start > /dev/null
    systemd_host "sd_${state}" "${state}" "${SESSION_CGROUP}"
    check "stop while the unit is ${state} runs in wazuh-control" "0" "$(control "sd_${state}" stop)"
    check "stop while the unit is ${state} only asks systemctl" "${PROBE}" \
        "$(systemctl_calls "sd_${state}")"
    check "stop while the unit is ${state} stops the daemons" "" "$(running "sd_${state}")"
done

# A restart or stop while systemctl stop is running goes after it, through systemctl.
new_tree sd_deactivating
control sd_deactivating start > /dev/null
systemd_host sd_deactivating deactivating "${SESSION_CGROUP}"
control sd_deactivating restart > /dev/null
check "restart while the unit is stopping goes to systemctl" \
    "${PROBE}
restart wazuh-agent.service" "$(systemctl_calls sd_deactivating)"

# systemctl reload fails on a unit that is stopping: the reload waits for the lock here.
new_tree sd_reload_deactivating
control sd_reload_deactivating start > /dev/null
agentd="$(cat "${WORK}/sd_reload_deactivating/var/run/wazuh-agentd"-*.pid)"
systemd_host sd_reload_deactivating deactivating "${SESSION_CGROUP}"
check "reload on a deactivating unit runs in wazuh-control" "0" "$(control sd_reload_deactivating reload)"
check "reload on a deactivating unit does not hand it to systemctl" "${PROBE}
--version" "$(systemctl_calls sd_reload_deactivating)"
check "reload on a deactivating unit keeps wazuh-agentd" "${agentd}" \
    "$(cat "${WORK}/sd_reload_deactivating/var/run/wazuh-agentd"-*.pid)"

# The unit's PIDFile= reached through a symlink to this installation, or this installation run
# through a symlink, is still this installation.
new_tree sd_symlink
control sd_symlink start > /dev/null
systemd_host sd_symlink active "${SESSION_CGROUP}"
ln -s "${WORK}/sd_symlink" "${WORK}/sd_symlink_link"
echo "${WORK}/sd_symlink_link/var/run/wazuh-agentd.pid" > "${WORK}/sd_symlink/unit-pidfile"
control sd_symlink stop > /dev/null
check "a PIDFile= through a symlink to this installation goes to systemctl" "${PROBE}
stop wazuh-agent.service" "$(systemctl_calls sd_symlink)"
echo "${WORK}/sd_symlink/var/run/wazuh-agentd.pid" > "${WORK}/sd_symlink/unit-pidfile"
rm -f "${WORK}/sd_symlink/systemctl.log"
PATH="${WORK}/sd_symlink/stubbin:${PATH}" "${WORK}/sd_symlink_link/bin/wazuh-control" stop > /dev/null 2>&1
check "wazuh-control run through a symlink to the installation goes to systemctl" "${PROBE}
stop wazuh-agent.service" "$(systemctl_calls sd_symlink)"
rm -f "${WORK}/sd_symlink_link"
drop_tree sd_symlink

# A second installation in another directory: the unit runs the first one.
new_tree sd_other_install
control sd_other_install start > /dev/null
systemd_host sd_other_install active "${SESSION_CGROUP}"
echo "/var/ossec/var/run/wazuh-agentd.pid" > "${WORK}/sd_other_install/unit-pidfile"
check "stop of another installation runs in wazuh-control" "0" "$(control sd_other_install stop)"
check "stop of another installation does not reach that unit" "show -p PIDFile wazuh-agent.service" \
    "$(systemctl_calls sd_other_install)"
check "stop of another installation stops its own daemons" "" "$(running sd_other_install)"

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

# A failed configuration test exits before this call takes the lock, so the lock it finds is
# someone else's (systemd's ExecStart, say) and must stay.
for action in restart start; do
    new_tree "badconf_lock_${action}"
    touch "${WORK}/badconf_lock_${action}/badconf-wazuh-syscheckd"
    mkdir -p "${WORK}/badconf_lock_${action}/var/start-script-lock"
    echo $$ > "${WORK}/badconf_lock_${action}/var/start-script-lock/pid"
    check "${action} with a configuration error fails" "1" "$(control "badconf_lock_${action}" "${action}")"
    check "${action} with a configuration error keeps a lock it did not take" "$$" \
        "$(cat "${WORK}/badconf_lock_${action}/var/start-script-lock/pid" 2>/dev/null)"
done

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
