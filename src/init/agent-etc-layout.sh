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

# Staged copies older layouts let the agent's atomic writes leave in etc/.
find "${ETC}" -maxdepth 1 -type f ! -user root \
    \( -name 'client.keys.??????' -o -name 'reenroll.secret.??????' \) -exec rm -f {} +

# A file in etc/ with more than one link stays reachable through its other name: replace it with an
# own copy, staged in a directory only root can enter. One that cannot be copied is removed.
if STAGE=$(mktemp -d "${DIR}/.etc-layout.XXXXXX"); then
    find "${ETC}" -maxdepth 1 -type f -links +1 -exec sh -c '
        stage="$1"
        shift
        for linked in "$@"; do
            if cp -p "${linked}" "${stage}/copy" && mv -fT "${stage}/copy" "${linked}"; then
                echo "${linked} had more than one link; replaced it with its own copy." >&2
            else
                rm -f "${stage}/copy" "${linked}"
                echo "${linked} had more than one link and could not be copied; removed it." >&2
            fi
        done' sh "${STAGE}" {} +
    rm -rf "${STAGE}"
fi

# Nothing directly in etc/ stays owned or writable by anyone but root.
find "${ETC}" -maxdepth 1 -type f -links 1 \( ! -user root -o -perm -020 -o -perm -002 \) \
    -exec chown root:"${GROUP}" {} + -exec chmod go-w {} +

# move_over <src> <dst>: rename onto dst, replacing a link there instead of moving into its target.
# If that fails (a directory at dst, or no mv -T), the file stays and wazuh-agentd moves it at start.
move_over() {
    mv -fT "$1" "$2" 2> /dev/null || echo "Could not move $1 to $2; the agent moves it when it starts." >&2
}

# move_legacy <name> <owner> <discard duplicate: yes|no>
# Owner and mode are set while the file is still in the root-only etc/: the agent user can swap
# entries in etc/keys, so nothing there is changed by name.
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
        chown "$2" "${old}" && chmod 0640 "${old}" && move_over "${old}" "${new}"
    elif [ ! -s "${old}" ] || [ "$3" = "yes" ]; then
        rm -f "${old}"
    else
        echo "Both ${old} and ${new} exist; the agent uses ${new}. Remove ${old} once checked." >&2
    fi
}

move_legacy client.keys root:"${GROUP}" no
# The agent rewrites the secret after dropping privileges, so it stays its own.
move_legacy reenroll.secret "${USER}":"${GROUP}" yes

# Staged copies the agent's atomic writes left in etc/keys; only old ones, so a write in progress
# keeps its copy, and not root's (rpm's .rpmnew, an admin's backup). rm never follows a link.
find "${KEYS}" -maxdepth 1 -type f -mmin +1 ! -user root ! -name '*.rpmnew' \
    \( -name 'client.keys.??????' -o -name 'reenroll.secret.??????' \) -exec rm -f {} +

exit 0
