#!/bin/bash
# Wazuh - Yara active response
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#------------------------- Gather parameters -------------------------#

# Static active response parameters
FILENAME=$8
LOCAL="$(dirname "$0")"

# Extra arguments
YARA_PATH=
YARA_RULES=

while [[ $# -gt 0 ]]
do

case "$1" in
    -yara_path)
    YARA_PATH="$2"
    shift
    shift
    ;;
    -yara_rules)
    YARA_RULES="$2"
    shift
    shift
    ;;
    *)
    shift # past argument
    ;;
esac
done

# Move to the active response directory
cd "$LOCAL" || exit 1
cd ../

# Set LOG_FILE path
PWD="$(pwd)"
LOG_FILE="${PWD}/../logs/active-responses.log"

#----------------------- Analyze parameters -----------------------#

if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]
then
    echo "wazuh-yara: ERROR - Yara active response error. Yara path and rules parameters are mandatory." >> "${LOG_FILE}"
    exit
fi

#------------------------- Main workflow --------------------------#

# Execute Yara scan on the specified filename
yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME")"

if [[ $yara_output != "" ]]
then
    # Iterate every detected rule and append it to the LOG_FILE
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> "${LOG_FILE}"
    done <<< "$yara_output"
fi

exit 1;