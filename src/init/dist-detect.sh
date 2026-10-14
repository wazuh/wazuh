#!/bin/sh

# Wazuh Distribution Detector
# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# The manager's RPM sources this file from %post, on hosts that may not have sed or grep: the version
# numbers it can reach there (os-release, CentOS, Fedora, Red Hat) are read with the shell only. Each
# helper prints exactly what the sed expression in its comment printed.

# DistNumber <text>: sed -rn 's/[^0-9]*([0-9]+).*/\1/p' -- the first run of digits.
DistNumber()
{
    _dn_rest="${1#"${1%%[0-9]*}"}"
    printf '%s' "${_dn_rest%%[!0-9]*}"
}

# DistMinor <text>: sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p' -- the digits after the first run of
# digits followed by a dot and a digit. Like the unanchored sed, what comes before that run's leading
# non-digits is kept in front ("15-SP5.1" gives "151").
DistMinor()
{
    _dm_done=""
    _dm_rest="$1"
    while :; do
        _dm_lead="${_dm_rest%%[0-9]*}"
        if [ "$_dm_lead" = "$_dm_rest" ]; then
            return 0
        fi
        _dm_tail="${_dm_rest#"$_dm_lead"}"
        _dm_num="${_dm_tail%%[!0-9]*}"
        _dm_tail="${_dm_tail#"$_dm_num"}"
        case "$_dm_tail" in
            .[0-9]*)
                _dm_tail="${_dm_tail#.}"
                printf '%s' "${_dm_done}${_dm_tail%%[!0-9]*}"
                return 0
                ;;
        esac
        _dm_done="${_dm_done}${_dm_lead}${_dm_num}"
        _dm_rest="$_dm_tail"
    done
}

# DistTwoDigits <text>: the leading digits of <text>, two at most.
DistTwoDigits()
{
    _dt_digits="${1%%[!0-9]*}"
    while [ "${#_dt_digits}" -gt 2 ]; do
        _dt_digits="${_dt_digits%?}"
    done
    printf '%s' "$_dt_digits"
}

# ReleaseNumber <file> major|minor: sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' (major) and
# sed -rn 's/.* [0-9]{1,2}\.*([0-9]{0,2}).*/\1/p' (minor). On each line, at the last space followed by
# a digit: its first one or two digits; for the minor, up to two digits after them and any dots.
ReleaseNumber()
{
    while IFS= read -r _rn_line || [ -n "$_rn_line" ]; do
        _rn_found=""
        _rn_rest="$_rn_line"
        while :; do
            case "$_rn_rest" in
                *" "*) _rn_rest="${_rn_rest#* }" ;;
                *) break ;;
            esac
            case "$_rn_rest" in
                [0-9]*) _rn_found="$_rn_rest" ;;
            esac
        done
        if [ -z "$_rn_found" ]; then
            continue
        fi
        _rn_major=$(DistTwoDigits "$_rn_found")
        if [ "$2" = "major" ]; then
            printf '%s\n' "$_rn_major"
        else
            _rn_found="${_rn_found#"$_rn_major"}"
            while :; do
                case "$_rn_found" in
                    .*) _rn_found="${_rn_found#.}" ;;
                    *) break ;;
                esac
            done
            printf '%s\n' "$(DistTwoDigits "$_rn_found")"
        fi
    done < "$1"
}

# FedoraNumber <file>: sed -rn 's/.* ([0-9]{1,2}) .*/\1/p' -- on each line, the last word of one or two
# digits with a space on both sides.
FedoraNumber()
{
    while IFS= read -r _fn_line || [ -n "$_fn_line" ]; do
        _fn_found=""
        _fn_rest="$_fn_line"
        while :; do
            case "$_fn_rest" in
                *" "*) _fn_rest="${_fn_rest#* }" ;;
                *) break ;;
            esac
            case "$_fn_rest" in
                [0-9]" "*|[0-9][0-9]" "*) _fn_found="${_fn_rest%% *}" ;;
            esac
        done
        if [ -n "$_fn_found" ]; then
            printf '%s\n' "$_fn_found"
        fi
    done < "$1"
}

# Default values
DIST_NAME="Linux"
DIST_VER="0"
DIST_SUBVER="0"

if [ -r "/etc/os-release" ]; then
    . /etc/os-release
    DIST_NAME=$ID
    DIST_VER=$(DistNumber "$VERSION_ID")
    if [ "X$DIST_VER" = "X" ]; then
        DIST_VER="0"
    fi
    if [ "$DIST_NAME" = "amzn" ] && [ "$DIST_VER" = "2018" ]; then
        DIST_VER="1"
    fi
    DIST_SUBVER=$(DistMinor "$VERSION_ID")
    if [ "X$DIST_SUBVER" = "X" ]; then
        DIST_SUBVER="0"
    fi
fi

if [ ! -r "/etc/os-release" ] || [ "$DIST_NAME" = "centos" ]; then
    # CentOS
    if [ -r "/etc/centos-release" ]; then
        DIST_NAME="centos"
        DIST_VER=$(ReleaseNumber /etc/centos-release major)
        DIST_SUBVER=$(ReleaseNumber /etc/centos-release minor)

    # Fedora
    elif [ -r "/etc/fedora-release" ]; then
        DIST_NAME="fedora"
        DIST_VER=$(FedoraNumber /etc/fedora-release)

    # RedHat
    elif [ -r "/etc/redhat-release" ]; then
        case "$(cat /etc/redhat-release)" in
            *CentOS*) DIST_NAME="centos" ;;
            *) DIST_NAME="rhel" ;;
        esac
        DIST_VER=$(ReleaseNumber /etc/redhat-release major)
        DIST_SUBVER=$(ReleaseNumber /etc/redhat-release minor)

    # Ubuntu
    elif [ -r "/etc/lsb-release" ]; then
        . /etc/lsb-release
        DIST_NAME="ubuntu"
        DIST_VER=$(echo $DISTRIB_RELEASE | sed -rn 's/.*([0-9][0-9])\.[0-9][0-9].*/\1/p')
        DIST_SUBVER=$(echo $DISTRIB_RELEASE | sed -rn 's/.*[0-9][0-9]\.([0-9][0-9]).*/\1/p')

    # Gentoo
    elif [ -r "/etc/gentoo-release" ]; then
        DIST_NAME="gentoo"
        DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.[0-9]{1,2}.*/\1/p' /etc/gentoo-release`
        DIST_SUBVER=`sed -rn 's/.* [0-9]{1,2}\.([0-9]{1,2}).*/\1/p' /etc/gentoo-release`

    # SuSE
    elif [ -r "/etc/SuSE-release" ]; then
        DIST_NAME="suse"
        DIST_VER=`sed -rn 's/.*VERSION = ([0-9]{1,2}).*/\1/p' /etc/SuSE-release`
        DIST_SUBVER=`sed -rn 's/.*PATCHLEVEL = ([0-9]{1,2}).*/\1/p' /etc/SuSE-release`
        if [ "$DIST_SUBVER" = "" ]; then #openSuse
          DIST_SUBVER=`sed -rn 's/.*VERSION = ([0-9]{1,2})\.([0-9]{1,2}).*/\1/p' /etc/SuSE-release`
        fi

    # Arch
    elif [ -r "/etc/arch-release" ]; then
        DIST_NAME="arch"
        DIST_VER=$(uname -r | sed -rn 's/[^0-9]*([0-9]+).*/\1/p')
        DIST_SUBVER=$(uname -r | sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p')

    # Debian
    elif [ -r "/etc/debian_version" ]; then
        DIST_NAME="debian"
        DIST_VER=`sed -rn 's/[^0-9]*([0-9]+).*/\1/p' /etc/debian_version`
        DIST_SUBVER=`sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p' /etc/debian_version`

    # Slackware
    elif [ -r "/etc/slackware-version" ]; then
        DIST_NAME="slackware"
        DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.[0-9].*/\1/p' /etc/slackware-version`
        DIST_SUBVER=`sed -rn 's/.* [0-9]{1,2}\.([0-9]).*/\1/p' /etc/slackware-version`

    # Darwin
    elif [ "$(uname)" = "Darwin" ]; then
        DIST_NAME="darwin"
        DIST_VER=$(uname -r | sed -En 's/[^0-9]*([0-9]+).*/\1/p')
        DIST_SUBVER=$(uname -r | sed -En 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p')

    # BSD
    elif [ "X$(uname)" = "XOpenBSD" -o "X$(uname)" = "XNetBSD" -o "X$(uname)" = "XFreeBSD" -o "X$(uname)" = "XDragonFly" ]; then
        DIST_NAME="bsd"
        DIST_VER=$(uname -r | sed -rn 's/[^0-9]*([0-9]+).*/\1/p')
        DIST_SUBVER=$(uname -r | sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p')

    elif [ "X$(uname)" = "XLinux" ]; then
        DIST_NAME="Linux"

    fi
    if [ "X$DIST_SUBVER" = "X" ]; then
        DIST_SUBVER="0"
    fi
fi
