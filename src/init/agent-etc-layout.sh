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

# move_legacy <name> <discard duplicate: yes|no>
move_legacy() {
    old="${ETC}/$1"
    new="${KEYS}/$1"

    if [ -L "${old}" ]; then
        rm -f "${old}"
        return 0
    fi

    if [ ! -f "${old}" ]; then
        return 0
    fi

    if [ -z "$(find "${old}" -prune -links 1)" ]; then
        echo "${old} has more than one link; not moving it to ${new}." >&2
        return 0
    fi

    if [ -d "${new}" ] && [ ! -L "${new}" ]; then
        echo "${new} is a directory; not moving ${old} into place." >&2
    elif [ -L "${new}" ] || [ ! -s "${new}" ]; then
        mv -f "${old}" "${new}"
    elif [ ! -s "${old}" ] || [ "$2" = "yes" ]; then
        rm -f "${old}"
    else
        echo "Both ${old} and ${new} exist; the agent uses ${new}. Remove ${old} once checked." >&2
    fi
}

move_legacy client.keys no
move_legacy reenroll.secret yes

# Staged copies the agent's own atomic writes left behind.
find "${ETC}" -maxdepth 1 -type f ! -user root \
    \( -name 'client.keys.??????' -o -name 'reenroll.secret.??????' \) -exec rm -f {} +

# Nothing directly in etc/ stays owned or writable by anyone but root.
find "${ETC}" -maxdepth 1 -type f -links 1 \( ! -user root -o -perm -020 -o -perm -002 \) \
    -exec chown root:"${GROUP}" {} + -exec chmod go-w {} +

if [ -f "${KEYS}/client.keys" ] && [ ! -L "${KEYS}/client.keys" ]; then
    chown root:"${GROUP}" "${KEYS}/client.keys"
    chmod 0640 "${KEYS}/client.keys"
fi

# The agent rewrites this one after dropping privileges, so it stays its own.
if [ -f "${KEYS}/reenroll.secret" ] && [ ! -L "${KEYS}/reenroll.secret" ]; then
    chown "${USER}":"${GROUP}" "${KEYS}/reenroll.secret"
    chmod 0640 "${KEYS}/reenroll.secret"
fi

exit 0
