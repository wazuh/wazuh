#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function commandErrorChecker() {
    if [ $? -eq 0 ]; then
        echo "Error: a blank space was inserted at beginning of $1 SCA field."
        error_found=1
    fi
}

error_found=0

grep -R "title: \" " ruleset/sca/
commandErrorChecker "title"
grep -R "description: \" " ruleset/sca/
commandErrorChecker "description"
grep -R "rationale: \" " ruleset/sca/
commandErrorChecker "rationale"
grep -R "remediation: \" " ruleset/sca/
commandErrorChecker "remediation"

if [ $error_found -eq 1 ]; then
    exit 1
fi