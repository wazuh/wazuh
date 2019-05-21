#!/bin/sh
# Adds an IP to perimeter OPNsense firewall alias
# Requirements: OPNsense firewall with an user with API Key configured
# Expect: srcip
# Copyright (C) 2019 Cloudfence.
# Author: Julio Camargo
# based on firewall-drop script - Copyright (C) 2015-2019, Wazuh Inc. / Ahmet Ozturk / 
# Daniel B. Cid (kudos!) / cgzones

# VARs
ARG1=""
ARG2=""
RULEID=""
ACTION=$1
USER=$2
IP=$3
PWD=$(pwd)
LOCK="${PWD}/opnsense-ban"
LOCK_PID="${PWD}/opnsense-ban/pid"

LOCAL=$(dirname $0);
cd $LOCAL
cd ../
filename=$(basename "$0")

LOG_FILE="${PWD}/../logs/active-responses.log"

echo "$(date) $0 $1 $2 $3 $4 $5" >> ${LOG_FILE}


# Checking for an IP
if [ "x${IP}" = "x" ]; then
   echo "$0: <action> <username> <ip>" 
   exit 1;
fi


# Configuration
KEY="YOURKEY"
SECRET="TELLMEYOURSECRET"
URL="https://<OPNSENSE_IPADDR>/api/firewall/alias_util/add/wazuh_activeresponse"
BLOCKIP="$IP"


#  
PAYLOAD='{"address": "'$BLOCKIP'"}'

curl -XPOST -d "$PAYLOAD" -H "Content-Type: application/json" -k -u "$KEY":"$SECRET" $URL
