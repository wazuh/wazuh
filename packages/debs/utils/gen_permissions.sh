#!/usr/bin/env /bin/bash
#
# Wazuh restore permissions script generator (ver 0.1)
# Copyright (C) 2019 Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
#
# This scripts take 2 parameters, source_dir and target_dir, and an optional
# third one, --guard-writable (see below)
# Remember: you must use gawk, be careful mawk is not compatible
#
# Usage: ./gen_permissions.sh /var/ossec/ ~/restore_permissions.sh [--guard-writable]

set -euo pipefail

# --guard-writable: the generated script runs as root, and a path below a
# directory that anyone but root can write (owned by another user, or
# group/other-writable) may be -- or pass through -- a link the service account
# planted, which chown/chmod would follow. Such paths go through fix() instead:
#   - a directory is entered with cd, and only acted on as "." once pwd -P
#     confirms the shell is in the expected place;
#   - a file is hard-linked (ln -P never follows a link) from its confirmed
#     parent into a root-only directory and acted on there, where nobody else
#     can swap it; a link, or a file with any other hard link, is left alone.
# Neither can be redirected after the check. Other paths keep the plain form.
GUARD_WRITABLE=0
if [ "${3:-}" = "--guard-writable" ]; then
    GUARD_WRITABLE=1
fi

# Symlinks are excluded: find reports them as mode 777 and chmod/chown on a
# symlink path dereference it, so restoring them would reset the target's
# permissions to 777 whenever the symlink entry follows the target's own.
find $1 -depth ! -type l -printf '%y:%m:%u:%g:%p\0' | awk -v RS='\0' -F: -v guard="${GUARD_WRITABLE}" '
BEGIN {
    q = "\047";
}
{
    p = $0;
    sub(/^[^:]*:/, "", p);
    n++;
    line[n] = p;
    f = $0;
    sub(/^[^:]*:[^:]*:[^:]*:[^:]*:/, "", f);
    # find echoes the starting point with the trailing slash it was given.
    if (f != "/") sub(/\/+$/, "", f);
    path[n] = f;
    seen[f] = 1;
    if (n == 1 || length(f) < length(base)) base = f;
    if ($1 == "d" && ($3 != "root" || substr($2, length($2) - 1, 1) ~ /[2367]/ || substr($2, length($2), 1) ~ /[2367]/)) {
        writable[f] = 1;
    }
}
END {
    print "#!/bin/sh";
    if (guard) {
        print "BASE=" q base q;
        print "REAL=$(cd -P -- \"$BASE\" && pwd -P) || exit 1";
        print "STAGE=$(mktemp -d \"$BASE/.restore-permissions.XXXXXX\") || exit 1";
        print "trap '\''rm -rf \"$STAGE\"'\'' EXIT";
        print "fix() {";
        print "    rel=${3#\"$BASE\"}";
        print "    if [ -d \"$3\" ] && [ ! -L \"$3\" ]; then";
        print "        (cd -P -- \"$3\" && [ \"$(pwd -P)\" = \"$REAL$rel\" ] && chown -- \"$2\" . && chmod -- \"$1\" .)";
        print "    else";
        print "        (cd -P -- \"${3%/*}\" && [ \"$(pwd -P)\" = \"$REAL${rel%/*}\" ] && ln -P -- \"${3##*/}\" \"$STAGE/f\") || return 0";
        print "        if [ -f \"$STAGE/f\" ] && [ ! -L \"$STAGE/f\" ] && [ \"$(stat -c %h \"$STAGE/f\")\" -eq 2 ]; then";
        print "            chown -- \"$2\" \"$STAGE/f\" && chmod -- \"$1\" \"$STAGE/f\"";
        print "        fi";
        print "        rm -f \"$STAGE/f\"";
        print "    fi";
        print "} > /dev/null 2>&1";
    }
    for (i = 1; i <= n; i++) {
        guarded = 0;
        if (guard) {
            d = path[i];
            while (sub(/\/[^\/]*$/, "", d) && (d in seen)) {
                if (d in writable) { guarded = 1; break; }
            }
        }
        $0 = line[i];
        gsub(q, q q "\\" q);
        f = $0;
        sub(/^[^:]*:[^:]*:[^:]*:/, "", f);
        if (guarded) {
            sub(/\/+$/, "", f);
            print "fix", $1, q $2 ":" $3 q, q f q, "|| :";
        } else {
            print "chown --", q $2 ":" $3 q, q f q, " > /dev/null 2>&1 || :";
            print "chmod", $1, q f q, " > /dev/null 2>&1 || :";
        }
    }
}' > $2
chmod +x $2
