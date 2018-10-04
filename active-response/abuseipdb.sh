#!/usr/bin/env bash
PWD=$(pwd)
# Enter API Key from AbuseIPDB
API_KEY=""
REPORT_URL="https://www.abuseipdb.com/report/json?"
# If you want to change the message, you have to encode it
COMMENT="Automatic%20report%20generated%20by%20Wazuh"
IP="$3"
# Web Attack
CATEGORY="21"
FULL_URL="${REPORT_URL}key=${API_KEY}&category=${CATEGORY}&comment=${COMMENT}&ip=${IP}"
LOG_FILE="${PWD}/../logs/active-responses.log"
curl "${FULL_URL}" | tee -a "${LOG_FILE}"
# Sample <command>
#   <command>
#    <name>abuse-ipdb</name>
#    <executable>abuseipdb.sh</executable>
#    <expect>srcip</expect>
#    <timeout_allowed>no</timeout_allowed>
# </command>
# Sample active-response
#  <active-response>
#    <command>abuse-ipdb</command>
#    <location>server</location>
#    <rules_group>appsec</rules_group>
#  </active-response>
