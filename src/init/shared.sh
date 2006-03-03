#!/bin/sh
# Shared variables and functions
# Author: Daniel B. Cid <daniel.cid@gmail.com>
# Last modification: Mar 03, 2006



### Setting up variables
VERSION_FILE="./src/VERSION"
VERSION=`cat ${VERSION_FILE}`
LOCATION="./src/LOCATION"
UNAME=`uname -snr`
NUNAME=`uname`
ME=`whoami`
HOST=`hostname`
NAMESERVERS=`cat /etc/resolv.conf | grep nameserver | cut -d " " -sf 2`
NAMESERVERS2=`cat /etc/resolv.conf | grep nameserver | cut -sf 2`
HOST_CMD=`which host`
CC=""
NAME="OSSEC HIDS"
INSTYPE="server"
DEFAULT_DIR=`grep DIR ${LOCATION} | cut -f2 -d\"`
INSTALLDIR="$DEFAULT_DIR";
WORKDIR="$INSTALLDIR"
NEWCONFIG="./etc/ossec.mc"
CEXTRA=""

# Internal definitions
NEWCONFIG="./etc/ossec.mc"
PRECONFIG="./etc/PRECONFIG"

## Languages (default to english)
LANGUAGE="en"

## Templates
TEMPLATE="./etc/templates"
ERROR="errors"
MSG="messages"

## Config templates
SYSCHECK_TEMPLATE="./etc/templates/config/syscheck.template"


## Host output
OSSECMX="ossec.net mail is handled by 10 mx.underlinux.com.br."
OSSECMX2="ossec.net mail is handled (pri=10) by mx.underlinux.com.br"


## EOF ##
