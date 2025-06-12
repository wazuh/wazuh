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

    LISTS_TO_INSERT=$(grep -Fvx -f "$OLD_LISTS_MANIFEST" "$NEW_LISTS_MANIFEST")

    if [ -n "$LISTS_TO_INSERT" ]; then
        LISTS_BLOCK=""
        for list in $LISTS_TO_INSERT; do
            LISTS_BLOCK="$LISTS_BLOCK\n    <list>$list</list>"
        done

        awk -v insert="$LISTS_BLOCK" '
        BEGIN {
            inside_ruleset = 0
            last_list_line = 0
            first_ruleset_found = 0
            ruleset_open_line = 0
            inside_comment = 0
        }

        {
            # Check for comment blocks
            if ($0 ~ /<!--/) {
            inside_comment = 1
            }
            if ($0 ~ /-->/) {
            inside_comment = 0
            }

            # Detect uncommented ruleset opening tag
            if (!inside_comment && $0 ~ /<ruleset>/ && !first_ruleset_found) {
            inside_ruleset = 1
            first_ruleset_found = 1
            ruleset_open_line = NR
            }

            # Track last <list> within uncommented ruleset
            if (!inside_comment && inside_ruleset && $0 ~ /<list>/) {
            last_list_line = NR
            }

            # Detect uncommented ruleset closing tag
            if (!inside_comment && inside_ruleset && $0 ~ /<\/ruleset>/) {
            inside_ruleset = 0
            }

            lines[NR] = $0
        }

        END {
            if (first_ruleset_found) {
            insert_line = (last_list_line > 0) ? last_list_line : ruleset_open_line
            for (i=1; i<=NR; i++) {
                print lines[i]
                if (i == insert_line) {
                print insert
                }
            }
            } else {
            # No uncommented <ruleset> found: print file as-is
            for (i=1; i<=NR; i++) {
                print lines[i]
            }
            }
        }
        ' "$CONFIG" > "$CONFIG.tmp" && mv "$CONFIG.tmp" "$CONFIG"
    fi


}
