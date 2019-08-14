#!/bin/sh

# Copyright (C) 2015-2019, Wazuh Inc.
# Shared variables and functions
# Author: Daniel B. Cid <daniel.cid@gmail.com>

### Setting up variables
VERSION_FILE="./src/VERSION"
REVISION_FILE="./src/REVISION"
VERSION=`cat ${VERSION_FILE}`
REVISION=`cat ${REVISION_FILE}`
LOCATION="./src/LOCATION"
UNAME=`uname -snr`
NUNAME=`uname`

# If whoami does not exist, try id
ls "`which whoami`" > /dev/null 2>&1
if [ ! $? = 0 ]; then
    ME=`id | cut -d " " -f 1`
    if [ "X${ME}" = "Xuid=0(root)" ]; then
        ME="root"
    fi
else
    ME=`whoami 2>/dev/null`
fi

OSSEC_INIT="/etc/ossec-init.conf"
HOST=`hostname`
NAMESERVERS=`cat /etc/resolv.conf | grep "^nameserver" | cut -d " " -sf 2`
NAMESERVERS2=`cat /etc/resolv.conf | grep "^nameserver" | cut -sf 2`
HOST_CMD=`which host 2>/dev/null`
NAME="Wazuh"
INSTYPE="server"
DEFAULT_DIR=`grep DIR ${LOCATION} | cut -f2 -d\"`
INSTALLDIR="$DEFAULT_DIR";
WORKDIR="$INSTALLDIR"
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
