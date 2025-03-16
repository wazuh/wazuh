#!/bin/sh

# Copyright (C) 2015, Wazuh Inc.
# Shared variables and functions
# Author: Daniel B. Cid <daniel.cid@gmail.com>

### Setting up variables
VERSION=$(awk -F'"' '/"version"[ \t]*:/ {print $4}' VERSION.json)
REVISION=$(awk -F'"' '/"stage"[ \t]*:/ {print $4}' VERSION.json)
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

# If hostname does not exist, try 'uname -n'
if command -v hostname > /dev/null 2>&1 ; then
    HOST=`hostname`
else
    HOST=`uname -n`
fi

OSSEC_INIT="/etc/ossec-init.conf"
NAMESERVERS=`cat /etc/resolv.conf | grep "^nameserver" | cut -d " " -sf 2`
NAMESERVERS2=`cat /etc/resolv.conf | grep "^nameserver" | cut -sf 2`
HOST_CMD=`command -v host 2>/dev/null`
NAME="Wazuh"
INSTYPE="server"
# Default installation directory
INSTALLDIR="/var/ossec";
PREINSTALLEDDIR=""
CEXTRA=""

# Internal definitions
NEWCONFIG="./etc/ossec.mc"
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
        THREADS=$(grep processor /proc/cpuinfo | wc -l)
        ;;
    Darwin)
        THREADS=$(sysctl -n hw.ncpu)
        ;;
    *)
        THREADS=1
    esac
fi
