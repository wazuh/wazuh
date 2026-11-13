#!/bin/bash

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Races two runs on the start-lock code of a control script. Sourced by test_wazuh_control.sh, which
# provides ${WORK}; the manager's copy of the code is checked to be the same there.
#
#   lock_race <control-script> before_open|after_open
#
# One run, the owner, creates the lock and stalls 7 s writing its pid: before the pid file's exclusive
# open, or between that open and the write. Another, the waiter, starts a second later, finds the lock
# pid-less for three rounds and reclaims it. Prints "one at a time", or "both held" if the owner went
# ahead too.

LOCK_RACE_STALL=7

# Takes the lock with the script's own code, then holds it for 4 s, noting whether another run already
# believed it held it.
race_waiter() {

    sh -c '
        LOCK=$1/var/start-script-lock; LOCK_PID=$LOCK/pid; RECLAIM=$LOCK.reclaim; RECLAIM_PID=$RECLAIM/pid
        MAX_ITERATION=40
        . "$2"
        wait_for_lock || exit 0
        [ -n "$(ls -d "$1"/holding.* 2>/dev/null)" ] && echo both >> "$1/result"
        mkdir "$1/holding.$$"
        sleep 4
        rmdir "$1/holding.$$"
    ' _ "$1" "$2"

}

# Creates the lock and stalls before writing its pid. before_open: between mkdir and write_pid, whose
# exclusive open must then fail on the waiter's pid file. after_open: inside write_pid, after the
# exclusive open, so take_dir() must find another pid when it reads its own back.
race_owner() {

    sh -c '
        LOCK=$1/var/start-script-lock; LOCK_PID=$LOCK/pid
        . "$2"
        if [ "$3" = before_open ]; then
            ( umask 022; mkdir "$LOCK" ) > /dev/null 2>&1
            sleep "$4"
            write_pid "$LOCK_PID" && [ "$(cat "$LOCK_PID" 2>/dev/null)" = "$$" ] || exit 0
        else
            stall=$4
            write_pid() {
                ( umask 022; set -C; exec 3> "$1"; sleep "${stall}"; echo "$$" >&3 ) > /dev/null 2>&1
            }
            take_dir "$LOCK" || exit 0
        fi
        [ -n "$(ls -d "$1"/holding.* 2>/dev/null)" ] && echo both >> "$1/result"
        mkdir "$1/holding.$$"
        sleep 4
        rmdir "$1/holding.$$"
    ' _ "$1" "$2" "$3" "${LOCK_RACE_STALL}"

}

lock_race() {

    local dir

    dir="$(mktemp -d "${WORK}/race.XXXXXX")"
    mkdir "${dir}/var"
    # The lock functions, from write_pid() up to the script's own lock().
    awk '/^write_pid\(\)/ {on=1} /^lock\(\)/ {on=0} on' "$1" > "${dir}/lock_code.sh"

    race_owner "${dir}" "${dir}/lock_code.sh" "$2" &
    sleep 1
    race_waiter "${dir}" "${dir}/lock_code.sh"
    wait

    [ -s "${dir}/result" ] && echo "both held" || echo "one at a time"

}
