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

## Templates
TEMPLATE="./etc/templates"
ERROR="errors"
MSG="messages"

## Config templates
SYSCHECK_TEMPLATE="./etc/templates/config/syscheck.template"
SYSLOG_TEMPLATE="./etc/templates/config/syslog-logs.template"
APACHE_TEMPLATE="./etc/templates/config/apache-logs.template"
SNORT_TEMPLATE="./etc/templates/config/snort-logs.template"
HOST_DENY_TEMPLATE="./etc/templates/config/ar-host-deny.template"
FIREWALL_DROP_TEMPLATE="./etc/templates/config/ar-firewall-drop.template"
DISABLE_ACCOUNT_TEMPLATE="./etc/templates/config/ar-disable-account.template"
ACTIVE_RESPONSE_TEMPLATE="./etc/templates/config/active-response.template"
RULES_TEMPLATE="./etc/templates/config/rules.template"


## Host output
OSSECMX="ossec.net mail is handled by 10 mx.underlinux.com.br."
OSSECMX2="ossec.net mail is handled (pri=10) by mx.underlinux.com.br"


## EOF ##
