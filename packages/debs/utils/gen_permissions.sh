#!/usr/bin/env /bin/bash
#
# Wazuh restore permissions script generator (ver 0.1)
# Copyright (C) Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
#
# This scripts take 2 parameters, source_dir and target_dir, and the optional
# --guard-writable and --guard-also (see below)
# Remember: you must use gawk, be careful mawk is not compatible
#
# Usage: ./gen_permissions.sh /var/ossec/ ~/restore_permissions.sh [--guard-writable [--guard-also <rel>]...]

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
#
# The root-only staging directory is created in the base directory itself: ln -P
# cannot cross a mount point, and the base directory may be one (a bind mount or
# a volume for /etc/wazuh-manager), so no directory above it can stage. The base
# directory may be writable by the service account, which could then rename the
# staging directory away and put a link in its place between the checks and the
# chown/chmod; the generated script therefore sets the sticky bit on it while it
# runs (only root may then rename a root-owned entry) and refuses a base
# directory root does not own (its owner may rename anything in it). The base
# directory's own entry, the last one, restores its mode, sticky bit included.
#
# --guard-also <rel>: also guard the paths below <rel> (relative to source_dir),
# whatever its mode in source_dir. For a directory that was writable by the
# service account on hosts installed by an older package, which may still hold
# its links when the generated script runs. Repeatable; needs --guard-writable.
GUARD_WRITABLE=0
GUARD_ALSO=""
SRC_DIR="$1"
DST_FILE="$2"
shift 2
while [ $# -gt 0 ]; do
    case "$1" in
        --guard-writable) GUARD_WRITABLE=1 ;;
        --guard-also)
            [ -n "${2:-}" ] || { echo "--guard-also needs a path" >&2; exit 1; }
            GUARD_ALSO="${GUARD_ALSO}${GUARD_ALSO:+:}${2#/}"
            shift ;;
        *) echo "Unknown option: ${1}" >&2; exit 1 ;;
    esac
    shift
done
if [ -n "${GUARD_ALSO}" ] && [ "${GUARD_WRITABLE}" = 0 ]; then
    echo "--guard-also needs --guard-writable" >&2
    exit 1
fi

# Symlinks are excluded: find reports them as mode 777 and chmod/chown on a
# symlink path dereference it, so restoring them would reset the target's
# permissions to 777 whenever the symlink entry follows the target's own.
find "${SRC_DIR}" -depth ! -type l -printf '%y:%m:%u:%g:%p\0' | awk -v RS='\0' -F: -v guard="${GUARD_WRITABLE}" -v also="${GUARD_ALSO}" '
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
    na = split(also, rel, ":");
    for (i = 1; i <= na; i++) {
        sub(/\/+$/, "", rel[i]);
        if (rel[i] != "") writable[base "/" rel[i]] = 1;
    }
    print "#!/bin/sh";
    if (guard) {
        print "BASE=" q base q;
        print "REAL=$(cd -P -- \"$BASE\" && pwd -P) || exit 1";
        print "[ \"$(stat -c %u -- \"$REAL\")\" = 0 ] || exit 1";
        print "case $(stat -c %A -- \"$REAL\") in *[tT]) STICKY=0 ;; *) STICKY=1 ;; esac";
        print "unsticky() {";
        print "    if [ $STICKY = 1 ]; then (cd -P -- \"$BASE\" && [ \"$(pwd -P)\" = \"$REAL\" ] && chmod -t .); fi";
        print "} > /dev/null 2>&1";
        print "if [ $STICKY = 1 ]; then (cd -P -- \"$BASE\" && [ \"$(pwd -P)\" = \"$REAL\" ] && chmod +t .) || exit 1; fi";
        print "STAGE=$(mktemp -d \"$BASE/.restore-permissions.XXXXXX\") || { unsticky; exit 1; }";
        print "trap '\''rm -rf \"$STAGE\"; unsticky'\'' EXIT";
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
}' > "${DST_FILE}"
chmod +x "${DST_FILE}"
