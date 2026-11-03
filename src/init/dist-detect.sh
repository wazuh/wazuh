#!/bin/sh

# Wazuh Distribution Detector
# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# The manager's and the agent's packages source this file from their scriptlets (and install.sh and the
# macOS postinstall on bash 3.2), on hosts that may not have sed or grep, so every version number is
# read with the shell only. Each helper prints exactly what the sed expression in its comment printed;
# the ones that end in "Lines" filter standard input line by line as `sed -rn 's/.../\1/p'` did, so a
# line that does not match prints nothing and every matching line prints its own result.

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

# DistPut <value> <read status>: the value, then a newline unless the line it came from had none (sed
# keeps a last line's missing newline).
DistPut()
{
    if [ "$2" = 0 ]; then
        printf '%s\n' "$1"
    else
        printf '%s' "$1"
    fi
}

# NumberLines major|minor: DistNumber (major) or DistMinor (minor) on each line of standard input,
# for the lines where the sed expression matched.
NumberLines()
{
    while :; do
        _nl_eol=0
        IFS= read -r _nl_line || _nl_eol=1
        if [ "$_nl_eol" != 0 ] && [ -z "$_nl_line" ]; then
            break
        fi
        if [ "$1" = "major" ]; then
            case "$_nl_line" in
                *[0-9]*) DistPut "$(DistNumber "$_nl_line")" "$_nl_eol" ;;
            esac
        else
            _nl_found=$(DistMinor "$_nl_line")
            if [ -n "$_nl_found" ]; then
                DistPut "$_nl_found" "$_nl_eol"
            fi
        fi
    done
}

# PairLines major|minor: sed -rn 's/.*([0-9][0-9])\.[0-9][0-9].*/\1/p' (major) and
# sed -rn 's/.*[0-9][0-9]\.([0-9][0-9]).*/\1/p' (minor) -- on each line, the last place holding two
# digits, a dot and two digits: the digits before the dot, or the two after it.
PairLines()
{
    while :; do
        _pl_eol=0
        IFS= read -r _pl_line || _pl_eol=1
        if [ "$_pl_eol" != 0 ] && [ -z "$_pl_line" ]; then
            break
        fi
        _pl_found=""
        _pl_rest="$_pl_line"
        while [ -n "$_pl_rest" ]; do
            case "$_pl_rest" in
                [0-9][0-9].[0-9][0-9]*) _pl_found="$_pl_rest" ;;
            esac
            _pl_rest="${_pl_rest#?}"
        done
        if [ -n "$_pl_found" ]; then
            if [ "$1" = "major" ]; then
                DistPut "${_pl_found%"${_pl_found#??}"}" "$_pl_eol"
            else
                _pl_found="${_pl_found#???}"
                DistPut "${_pl_found%"${_pl_found#??}"}" "$_pl_eol"
            fi
        fi
    done
}

# DottedLines major|minor <width>: on each line, the last space followed by one or two digits, a dot
# and a digit; the digits before the dot (major), or up to <width> digits after it (minor). Width 2:
# sed -rn 's/.* ([0-9]{1,2})\.[0-9]{1,2}.*/\1/p' and 's/.* [0-9]{1,2}\.([0-9]{1,2}).*/\1/p' (Gentoo);
# width 1: sed -rn 's/.* ([0-9]{1,2})\.[0-9].*/\1/p' and 's/.* [0-9]{1,2}\.([0-9]).*/\1/p'
# (Slackware).
DottedLines()
{
    while :; do
        _dl_eol=0
        IFS= read -r _dl_line || _dl_eol=1
        if [ "$_dl_eol" != 0 ] && [ -z "$_dl_line" ]; then
            break
        fi
        _dl_found=""
        _dl_rest="$_dl_line"
        while :; do
            case "$_dl_rest" in
                *" "*) _dl_rest="${_dl_rest#* }" ;;
                *) break ;;
            esac
            case "$_dl_rest" in
                [0-9].[0-9]*|[0-9][0-9].[0-9]*) _dl_found="$_dl_rest" ;;
            esac
        done
        if [ -z "$_dl_found" ]; then
            continue
        fi
        _dl_major="${_dl_found%%.*}"
        if [ "$1" = "major" ]; then
            DistPut "$_dl_major" "$_dl_eol"
        else
            _dl_minor=$(DistTwoDigits "${_dl_found#"$_dl_major".}")
            if [ "$2" = "1" ]; then
                _dl_minor="${_dl_minor%"${_dl_minor#?}"}"
            fi
            DistPut "$_dl_minor" "$_dl_eol"
        fi
    done
}

# MarkerLines <marker> [dotted]: on each line, the last <marker> followed by a digit: its first one or
# two digits -- sed -rn 's/.*VERSION = ([0-9]{1,2}).*/\1/p' with "VERSION = ". With "dotted", the
# last <marker> followed by one or two digits, a dot and a digit, and again the digits before the dot:
# sed -rn 's/.*VERSION = ([0-9]{1,2})\.([0-9]{1,2}).*/\1/p', which prints its first group, not the
# second (SuSE's fallback for the patch level has always taken the major from that line).
MarkerLines()
{
    while :; do
        _ml_eol=0
        IFS= read -r _ml_line || _ml_eol=1
        if [ "$_ml_eol" != 0 ] && [ -z "$_ml_line" ]; then
            break
        fi
        _ml_found=""
        _ml_rest="$_ml_line"
        while :; do
            case "$_ml_rest" in
                *"$1"*) _ml_rest="${_ml_rest#*"$1"}" ;;
                *) break ;;
            esac
            if [ "$2" = "dotted" ]; then
                case "$_ml_rest" in
                    [0-9].[0-9]*|[0-9][0-9].[0-9]*) _ml_found="$_ml_rest" ;;
                esac
            else
                case "$_ml_rest" in
                    [0-9]*) _ml_found="$_ml_rest" ;;
                esac
            fi
        done
        if [ -n "$_ml_found" ]; then
            DistPut "$(DistTwoDigits "$_ml_found")" "$_ml_eol"
        fi
    done
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
        DIST_VER=$(echo $DISTRIB_RELEASE | PairLines major)
        DIST_SUBVER=$(echo $DISTRIB_RELEASE | PairLines minor)

    # Gentoo
    elif [ -r "/etc/gentoo-release" ]; then
        DIST_NAME="gentoo"
        DIST_VER=$(DottedLines major 2 < /etc/gentoo-release)
        DIST_SUBVER=$(DottedLines minor 2 < /etc/gentoo-release)

    # SuSE
    elif [ -r "/etc/SuSE-release" ]; then
        DIST_NAME="suse"
        DIST_VER=$(MarkerLines "VERSION = " < /etc/SuSE-release)
        DIST_SUBVER=$(MarkerLines "PATCHLEVEL = " < /etc/SuSE-release)
        if [ "$DIST_SUBVER" = "" ]; then #openSuse
          DIST_SUBVER=$(MarkerLines "VERSION = " dotted < /etc/SuSE-release)
        fi

    # Arch
    elif [ -r "/etc/arch-release" ]; then
        DIST_NAME="arch"
        DIST_VER=$(uname -r | NumberLines major)
        DIST_SUBVER=$(uname -r | NumberLines minor)

    # Debian
    elif [ -r "/etc/debian_version" ]; then
        DIST_NAME="debian"
        DIST_VER=$(NumberLines major < /etc/debian_version)
        DIST_SUBVER=$(NumberLines minor < /etc/debian_version)

    # Slackware
    elif [ -r "/etc/slackware-version" ]; then
        DIST_NAME="slackware"
        DIST_VER=$(DottedLines major 1 < /etc/slackware-version)
        DIST_SUBVER=$(DottedLines minor 1 < /etc/slackware-version)

    # Darwin
    elif [ "$(uname)" = "Darwin" ]; then
        DIST_NAME="darwin"
        DIST_VER=$(uname -r | NumberLines major)
        DIST_SUBVER=$(uname -r | NumberLines minor)

    # BSD
    elif [ "X$(uname)" = "XOpenBSD" -o "X$(uname)" = "XNetBSD" -o "X$(uname)" = "XFreeBSD" -o "X$(uname)" = "XDragonFly" ]; then
        DIST_NAME="bsd"
        DIST_VER=$(uname -r | NumberLines major)
        DIST_SUBVER=$(uname -r | NumberLines minor)

    elif [ "X$(uname)" = "XLinux" ]; then
        DIST_NAME="Linux"

    fi
    if [ "X$DIST_SUBVER" = "X" ]; then
        DIST_SUBVER="0"
    fi
fi
