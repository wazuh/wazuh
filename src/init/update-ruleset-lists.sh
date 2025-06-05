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
        awk -v insert="$LISTS_BLOCK" '
        BEGIN {
            inserted = 0           # Flag to track insertion
            inside_ruleset = 0     # Flag if inside <ruleset>
            last_list_line = 0     # Line number of last <list> inside <ruleset>
        }

        # Detect start of <ruleset>
        /<ruleset>/ {
            print                 # Print <ruleset> line
            inside_ruleset = 1
            next
        }

        # When inside <ruleset>, track <list> lines and print normally
        inside_ruleset {
            if ($0 ~ /<list>/) {
            last_list_line = NR
            print
            next
            }

            # If we are at the line immediately after last <list>, insert
            if (last_list_line && NR == last_list_line + 1 && !inserted) {
            print insert        # Insert the new <list> entries
            inserted = 1
            }
            # If no <list> found and this is first line inside ruleset after <ruleset>
            else if (!last_list_line && !inserted) {
            print insert
            inserted = 1
            }
        }

        # Print the current line
        { print }

        # Detect end of <ruleset>
        /<\/ruleset>/ {
            inside_ruleset = 0
        }
        ' "$CONFIG" > "$CONFIG.tmp" && mv "$CONFIG.tmp" "$CONFIG"

    fi

}
