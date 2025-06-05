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

        for list in $LISTS_TO_INSERT; do
        LISTS_BLOCK="$LISTS_BLOCK\n    <list>$list</list>"
        done


        # Insert after the latest <list> at the first uncommented <ruleset> entry
        awk -v insert_lines="$LISTS_BLOCK" '
            BEGIN {
            in_comment=0
            in_ruleset=0
            last_list_line=0
            line_count=0
            }
            {
            line_count++
            lines[line_count] = $0

            if ($0 ~ /<!--/) in_comment=1
            if ($0 ~ /-->/) in_comment=0

            if (!in_comment && $0 ~ /<ruleset>/ && in_ruleset==0) {
                in_ruleset=1
            }

            if (in_ruleset && !in_comment && $0 ~ /<list>/) {
                last_list_line = line_count
            }

            if (!in_comment && $0 ~ /<\/ruleset>/ && in_ruleset==1) {
                in_ruleset=0
            }
            }
            END {
            for (i=1; i<=line_count; i++) {
                print lines[i]
                if (i == last_list_line) {
                printf("%s\n", insert_lines)
                }
            }
            }
        ' "$CONFIG" > "$CONFIG.tmp" && mv "$CONFIG.tmp" "$CONFIG"

    fi

}
