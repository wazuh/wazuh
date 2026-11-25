#!/bin/sh

# Copyright (C) Wazuh Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Agent etc/ layout: etc/ belongs to root, and the credentials the agent rotates after dropping
# privileges (client.keys, reenroll.secret) live in etc/keys/, the only part of etc/ its user may
# write. Moves them from their old paths and takes back anything older layouts left writable.
# Idempotent; run as root on every install and upgrade (packages, install.sh).
#
# Usage: agent-etc-layout.sh <installation dir> [group] [user]
# Exits 1 only when etc/ itself could not be locked; anything else is reported on stderr.

warn() {
    echo "$*" >&2
}

# path_is_root_only <path>: <path> and every directory above it belong to root and are not group-
# or other-writable, so only root can change what the path leads to.
path_is_root_only() {
    p="$1"
    while :; do
        [ -n "$(find "${p}" -prune -user root ! -perm -020 ! -perm -002 2> /dev/null)" ] || return 1
        [ "${p}" = "/" ] && return 0
        p=$(dirname "${p}")
    done
}

# link_is_safe <link>: only root can change the file <link> leads to, or create it if missing.
link_is_safe() {
    target=$(readlink -f "$1") && [ -n "${target}" ] || return 1
    if [ -e "${target}" ]; then
        [ -f "${target}" ] && path_is_root_only "${target}"
    else
        path_is_root_only "$(dirname "${target}")"
    fi
}

# replace_with_copy <entry>: a copy made in the root-only stage is renamed over <entry>.
replace_with_copy() {
    [ -n "${STAGE}" ] || return 1
    if cp -pL "$1" "${STAGE}/copy" && { [ ! -L "$1" ] || rm -f "$1"; } && mv -f "${STAGE}/copy" "$1"; then
        return 0
    fi
    rm -f "${STAGE}/copy"
    return 1
}

# lock_entry <entry>: a link, or a file with more than one link, directly in etc/. Either stays
# reachable through a path the agent user may control, which the ownership pass cannot take back.
lock_entry() {
    entry="$1"
    if [ -L "${entry}" ]; then
        # A link to a directory (etc/shared) is left alone.
        if [ -d "${entry}" ] || link_is_safe "${entry}"; then
            return 0
        fi
        if [ -f "${entry}" ] && replace_with_copy "${entry}"; then
            warn "${entry} led to a file users other than root can change; replaced it with a copy."
        else
            rm -f "${entry}"
            warn "${entry} led to a file users other than root can change; removed the link."
        fi
    elif [ -n "$(find "${entry}" -prune -type f -links +1)" ]; then
        if replace_with_copy "${entry}"; then
            warn "${entry} had more than one link; replaced it with its own copy."
        # Its group is kept: the other name may belong to another file owner.
        elif chown root "${entry}" && chmod go-w "${entry}"; then
            warn "${entry} had more than one link and could not be copied; made it root's in place."
        else
            warn "${entry} had more than one link and could not be copied or made root's."
        fi
    fi
}

# Run by find below, so that every name reaches lock_entry whole, newlines included.
if [ "$1" = "--lock-entries" ]; then
    STAGE="$2"
    shift 2
    for entry in "$@"; do
        lock_entry "${entry}"
    done
    exit 0
fi

DIR="$1"
GROUP="${2:-wazuh}"
USER="${3:-wazuh}"
ETC="${DIR}/etc"
KEYS="${ETC}/keys"

if [ -z "${DIR}" ] || [ ! -d "${ETC}" ] || [ -L "${ETC}" ]; then
    exit 0
fi

# First, so nothing below can be raced by the agent user.
chown root:"${GROUP}" "${ETC}"
chmod 0750 "${ETC}"

# Anything but a directory here was left while the agent user could write etc/.
if [ -L "${KEYS}" ] || { [ -e "${KEYS}" ] && [ ! -d "${KEYS}" ]; }; then
    rm -f "${KEYS}"
fi

mkdir -p "${KEYS}"
# Not sticky: the agent renames over a root-owned client.keys when it rotates it.
chown root:"${GROUP}" "${KEYS}"
chmod 0770 "${KEYS}"

# Staged copies older layouts let the agent's atomic writes leave in etc/, and stages an
# interrupted run of this script left.
find "${ETC}" -maxdepth 1 -type f ! -user root \
    \( -name 'client.keys.??????' -o -name 'reenroll.secret.??????' \) -exec rm -f {} +
find "${ETC}" -mindepth 1 -maxdepth 1 -type d -name '.etc-layout.??????' -exec rm -rf {} +

# Links, and files with more than one link. The credentials' links are removed further down.
if ! STAGE=$(mktemp -d "${ETC}/.etc-layout.XXXXXX"); then
    STAGE=
    warn "Could not create a staging directory in ${ETC}; linked files there are not replaced by copies."
fi
find "${ETC}" -mindepth 1 -maxdepth 1 \
    \( -type l ! -name client.keys ! -name reenroll.secret -o -type f -links +1 \) \
    -exec sh "$0" --lock-entries "${STAGE}" {} +
[ -z "${STAGE}" ] || rm -rf "${STAGE}"

# Nothing directly in etc/ stays owned or writable by anyone but root.
find "${ETC}" -maxdepth 1 -type f -links 1 \( ! -user root -o -perm -020 -o -perm -002 \) \
    -exec chown root:"${GROUP}" {} + -exec chmod go-w {} +

# move_over <src> <dst>: rename onto dst, replacing a link there instead of moving into its target.
move_over() {
    mv -fT "$1" "$2" 2> /dev/null || warn "Could not move $1 to $2; wazuh-agentd tries again when it starts."
}

# legacy_file <name>: etc/<name> is a regular file with a single link. A link there is removed.
legacy_file() {
    if [ -L "${ETC}/$1" ]; then
        rm -f "${ETC}/$1"
        warn "${ETC}/$1 was a link; removed it."
        return 1
    fi
    [ -f "${ETC}/$1" ] || return 1
    if [ -z "$(find "${ETC}/$1" -prune -links 1)" ]; then
        warn "${ETC}/$1 has more than one link; not moving it to ${KEYS}/$1."
        return 1
    fi
}

# adopt <name> <owner>: owner and mode are set while the file is still in the root-only etc/, since
# the agent user can swap entries in etc/keys and nothing there is changed by name.
adopt() {
    chown "$2" "${ETC}/$1" && chmod 0640 "${ETC}/$1" && move_over "${ETC}/$1" "${KEYS}/$1"
}

# A credential in the root-only etc/ that is no longer needed.
discard() {
    shred -u "${ETC}/$1" 2> /dev/null || rm -f "${ETC}/$1"
}

# KEY: "moved" when a key from etc/ took the place of the one in etc/keys, "kept" when it stays in
# etc/. The secret goes with the key it was issued for.
KEY=none
if legacy_file client.keys; then
    if [ -d "${KEYS}/client.keys" ] && [ ! -L "${KEYS}/client.keys" ]; then
        warn "${KEYS}/client.keys is a directory; not moving ${ETC}/client.keys into place."
        KEY=kept
    elif [ -L "${KEYS}/client.keys" ] || [ ! -s "${KEYS}/client.keys" ]; then
        [ -s "${ETC}/client.keys" ] && KEY=moved
        adopt client.keys root:"${GROUP}"
        [ -s "${ETC}/client.keys" ] && KEY=kept
    elif [ ! -s "${ETC}/client.keys" ]; then
        rm -f "${ETC}/client.keys"
    else
        warn "Both ${ETC}/client.keys and ${KEYS}/client.keys exist; the agent uses ${KEYS}/client.keys. Remove ${ETC}/client.keys once checked."
        KEY=kept
    fi
fi

# The agent rewrites the secret after dropping privileges, so it is handed to the agent user.
if legacy_file reenroll.secret; then
    if [ "${KEY}" = "kept" ]; then
        :
    elif [ -d "${KEYS}/reenroll.secret" ] && [ ! -L "${KEYS}/reenroll.secret" ]; then
        warn "${KEYS}/reenroll.secret is a directory; not moving ${ETC}/reenroll.secret into place."
    elif [ "${KEY}" = "moved" ] || [ -L "${KEYS}/reenroll.secret" ] || [ ! -s "${KEYS}/reenroll.secret" ]; then
        adopt reenroll.secret "${USER}":"${GROUP}"
    else
        discard reenroll.secret
    fi
elif [ "${KEY}" = "moved" ] && { [ -e "${KEYS}/reenroll.secret" ] || [ -L "${KEYS}/reenroll.secret" ]; }; then
    # rm never follows a link.
    rm -f "${KEYS}/reenroll.secret"
    warn "Removed ${KEYS}/reenroll.secret: the key from ${ETC}/client.keys replaced the one it was issued for."
fi

# Staged copies the agent's atomic writes left in etc/keys; only old ones, so a write in progress
# keeps its copy, and not root's (rpm's .rpmnew, an admin's backup). rm never follows a link.
find "${KEYS}" -maxdepth 1 -type f -mmin +1 ! -user root ! -name '*.rpmnew' \
    \( -name 'client.keys.??????' -o -name 'reenroll.secret.??????' \) -exec rm -f {} +

# Check the result. Ownership only means something when run as root, as the packages do.
STATUS=0
if [ "$(id -u)" = "0" ]; then
    LOCKED=$(find "${ETC}" -prune -user root ! -perm -020 ! -perm -002)
else
    LOCKED=$(find "${ETC}" -prune ! -perm -020 ! -perm -002)
fi
if [ -z "${LOCKED}" ]; then
    warn "WARNING: ${ETC} could not be locked: users other than root can still change it."
    STATUS=1
fi
find "${ETC}" -mindepth 1 -maxdepth 1 -type f \( -perm -020 -o -perm -002 \) \
    -exec printf 'WARNING: %s is still writable by users other than root.\n' {} + >&2
if [ "$(id -u)" = "0" ]; then
    # A secret that could not be moved stays the agent user's, as in etc/keys.
    find "${ETC}" -mindepth 1 -maxdepth 1 -type f ! -user root ! -name reenroll.secret \
        -exec printf 'WARNING: %s still does not belong to root.\n' {} + >&2
fi

exit "${STATUS}"
