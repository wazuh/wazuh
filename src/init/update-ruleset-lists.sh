#!/bin/sh

# Copyright (C) 2015, Wazuh Inc.
# All rights reserved.
# Wazuh.com

# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


updateRulesetLists()
{
    local CONFIG=$1
    local OLD_LISTS_MANIFEST=$2
    local NEW_LISTS_MANIFEST=$3

    LISTS_TO_INSERT=`grep -Fvx -f $OLD_LISTS_MANIFEST $NEW_LISTS_MANIFEST`

    if [ -n "$LISTS_TO_INSERT" ]; then

        XML_BLOCK="<ossec_config>\n"
        XML_BLOCK+="  <ruleset>\n"

        while IFS= read -r list; do
            XML_BLOCK+="    <list>$list</list>\n"
        done <<< "$LISTS_TO_INSERT"

        XML_BLOCK+="  </ruleset>\n"
        XML_BLOCK+="</ossec_config>"

        echo "$XML_BLOCK" >> $CONFIG
    fi

}
