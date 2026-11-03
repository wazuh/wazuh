#!/bin/sh

# Copyright (C) Wazuh Inc.
# Shared variables and functions
# Author: Daniel B. Cid <daniel.cid@gmail.com>

### Setting up variables
# The package scripts source this file on hosts that may not have awk, grep or hostname: every value
# below is read with the shell and coreutils only.

# JsonString <file> <key>: the string value of every `"key": "value"` line of <file>, one per line --
# the fourth "-separated field of the lines where "<key>" is followed by blanks and a colon.
JsonString()
{
    _js_tab=$(printf '\t')
    while IFS= read -r _js_line || [ -n "$_js_line" ]; do
        _js_after="${_js_line#*\"$2\"}"
        if [ "$_js_after" = "$_js_line" ]; then
            continue
        fi
        while :; do
            case "$_js_after" in
                " "*|"$_js_tab"*) _js_after="${_js_after#?}" ;;
                *) break ;;
            esac
        done
        case "$_js_after" in
            :*) ;;
            *) continue ;;
        esac
        # Fields 1-3 end at the first three quotes; the value is what follows, up to the next one.
        case "$_js_line" in
            *\"*\"*\"*) _js_value="${_js_line#*\"*\"*\"}" ;;
            *) printf '\n'; continue ;;
        esac
        case "$_js_value" in
            *\"*) printf '%s\n' "${_js_value%%\"*}" ;;
            *) printf '%s\n' "$_js_value" ;;
        esac
    done < "$1"
}

# LineFields <file> <prefix> <delimiter>: for each line that starts with <prefix> and holds <delimiter>,
# its second <delimiter>-separated field -- `grep "^<prefix>" <file> | cut -d <delimiter> -sf 2`.
LineFields()
{
    while IFS= read -r _lf_line || [ -n "$_lf_line" ]; do
        case "$_lf_line" in
            "$2"*) ;;
            *) continue ;;
        esac
        case "$_lf_line" in
            *"$3"*)
                _lf_field="${_lf_line#*"$3"}"
                printf '%s\n' "${_lf_field%%"$3"*}"
                ;;
        esac
    done < "$1"
}

# CountLines <file> <text>: how many lines of <file> contain <text> -- `grep <text> <file> | wc -l`.
CountLines()
{
    _cl_count=0
    while IFS= read -r _cl_line || [ -n "$_cl_line" ]; do
        case "$_cl_line" in
            *"$2"*) _cl_count=$((_cl_count + 1)) ;;
        esac
    done < "$1"
    printf '%s\n' "$_cl_count"
}

VERSION="v$(JsonString VERSION.json version)"
REVISION=$(JsonString VERSION.json stage)
UNAME=`uname -snr`
NUNAME=`uname`
VUNAME=`uname -r`

# If whoami does not exist, try id
if command -v whoami > /dev/null 2>&1 ; then
    ME=`whoami`
else
    ME=`id | cut -d " " -f 1`
    if [ "X${ME}" = "Xuid=0(root)" ]; then
        ME="root"
    fi
fi

# The node name, which is what hostname(1) prints.
HOST=`uname -n`

# The nameserver lines of resolv.conf, their second field split by a space and by a tab.
NAMESERVERS=""
NAMESERVERS2=""
if [ -r /etc/resolv.conf ]; then
    NAMESERVERS=$(LineFields /etc/resolv.conf nameserver " ")
    NAMESERVERS2=$(LineFields /etc/resolv.conf nameserver "$(printf '\t')")
fi
HOST_CMD=`command -v host 2>/dev/null`
NAME="Wazuh"
INSTYPE="manager"
# Default installation directory
INSTALLDIR="/var/wazuh-manager";
# The manager's configuration directory. Fixed: a custom installation directory moves the home only.
# Kept identical with WAZUH_MANAGER_CONF_DIR in defs.h, Utils::MANAGER_CONF_DIR
# (shared_modules/utils/managerConfDir.hpp), the engine's base/managerConfig.hpp, CONF_PATH in
# framework/wazuh/core/common.py and CONF_DIR in wazuh-server.sh and the package scripts.
CONF_DIR="/etc/wazuh-manager"
PREINSTALLEDDIR=""
CEXTRA=""
WAZUH_CONF="wazuh-manager.conf"
WAZUH_LOGFILE="wazuh-manager.log"
WAZUH_LOGJSON="wazuh-manager.json"

# Internal definitions
NEWCONFIG="./etc/wazuh.mc"
PRECONFIG="./etc/PRECONFIG"

## Templates
TEMPLATE="./etc/templates"
ERROR="errors"
MSG="messages"

## Host output
OSSECMX="devmail.ossec.net mail is handled by 10 ossec.mooo.com."
OSSECMX2="devmail.ossec.net mail is handled (pri=10) by ossec.mooo.com"
OSSECMX3="devmail.ossec.net mail is handled by 10 ossec.mooo.COM."

## Predefined file
PREDEF_FILE="./etc/preloaded-vars.conf"

# Get number of processors
if [ -z "$THREADS" ]
then
    case $(uname) in
    Linux)
        THREADS=$(CountLines /proc/cpuinfo processor)
        ;;
    Darwin)
        THREADS=$(sysctl -n hw.ncpu)
        ;;
    *)
        THREADS=1
    esac
fi
