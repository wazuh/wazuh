#!/bin/sh
# Shared variables and functions
# Author: Daniel B. Cid <daniel.cid@gmail.com>

### Setting up variables
VERSION_FILE="./src/VERSION"
VERSION=`cat ${VERSION_FILE}`
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
HOST_CMD=`which host`
NAME="OSSEC HIDS"
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

## Config templates
SYSCHECK_TEMPLATE="./etc/templates/config/syscheck.template"
SYSLOG_TEMPLATE="./etc/templates/config/syslog-logs.template"
APACHE_TEMPLATE="./etc/templates/config/apache-logs.template"
SNORT_TEMPLATE="./etc/templates/config/snort-logs.template"
PGSQL_TEMPLATE="./etc/templates/config/pgsql-logs.template"
HOST_DENY_TEMPLATE="./etc/templates/config/ar-host-deny.template"
FIREWALL_DROP_TEMPLATE="./etc/templates/config/ar-firewall-drop.template"
DISABLE_ACCOUNT_TEMPLATE="./etc/templates/config/ar-disable-account.template"
ACTIVE_RESPONSE_TEMPLATE="./etc/templates/config/active-response.template"
ROUTENULL_TEMPLATE="./etc/templates/config/ar-routenull.template"
RULES_TEMPLATE="./etc/templates/config/rules.template"

## Host output
OSSECMX="devmail.ossec.net mail is handled by 10 ossec.mooo.com."
OSSECMX2="devmail.ossec.net mail is handled (pri=10) by ossec.mooo.com"
OSSECMX3="devmail.ossec.net mail is handled by 10 ossec.mooo.COM."

## Predefined file
PREDEF_FILE="./etc/preloaded-vars.conf"

