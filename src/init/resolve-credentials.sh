#!/bin/sh

# Wazuh manager credential resolution
# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# The one place the manager resolves its credentials, so the Debian postinst, the RPM post scriptlet and
# install.sh cannot drift apart.
#
# The Server API accounts are owned by this node, so they are generated unless INITIAL_WAZUH_PASSWORD or
# INITIAL_WAZUH_WUI_PASSWORD supplies one. The indexer's `wazuh-manager` account is consumed: only the
# deployment knows it, so INDEXER_PASSWORD has to carry it and there is nothing to fall back to.
#
# A missing consumed credential leaves the node unconfigured rather than half configured: what resolved is
# applied, what did not is not written, the service is left alone, and the report names each account. No
# password is ever printed; the generated ones are in the credentials file, which the report names.
#
# Usage: resolve-credentials.sh <installdir> [--container]
#
# --container is for the image entrypoints in wazuh-docker and wazuh-kubernetes; nothing in this repository
# passes it, since its two container environments provision their own API credentials.
#
# Exit status: 0 on a package installation even when something is missing, because a maintainer script that
# fails leaves the package half-installed over a state the operator can still fix. 1 with --container, where
# no operator is going to fix anything.

DIR="$1"
MODE="$2"

if [ -z "${DIR}" ]; then
    echo "Usage: $0 <installdir> [--container]" >&2
    exit 2
fi

CREDENTIALS_FILE="${DIR}/api/configuration/security/wazuh-preseeded-passwords.yml"
KEYSTORE="${DIR}/bin/wazuh-manager-keystore"
RBAC_CONTROL="${DIR}/bin/rbac_control"
DOCUMENTATION="https://documentation.wazuh.com/current/installation-guide/wazuh-server/"

MISSING=""

resolved()
{
    printf '  resolved   %s\n' "$1"
}

missing()
{
    printf '  MISSING    %s\n' "$1"
    MISSING="yes"
}

# Owned: generated here unless the INITIAL_* variables supply them. Its output is captured because this
# script owns the report; it is echoed only when the call fails, where it names the reason.
if PROVISION_OUTPUT=$("${RBAC_CONTROL}" provision-passwords 2>&1); then
    # It exits 0 both when it provisioned and when it found a database it must not touch, and only the
    # first of those is something this script applied.
    case "${PROVISION_OUTPUT}" in
        *"already exists"*) resolved "Server API passwords already set on this node" ;;
        *) resolved "Server API passwords for wazuh and wazuh-wui, in ${CREDENTIALS_FILE}" ;;
    esac
else
    printf '%s\n' "${PROVISION_OUTPUT}" >&2
    missing "Server API passwords for wazuh and wazuh-wui"
fi

# Consumed: through the standard input, never through the tool's -v option, which would put the password on
# a command line every account on the host can read.
INDEXER_ACCOUNT="${INDEXER_USERNAME:-wazuh-manager}"
if [ -z "${INDEXER_PASSWORD}" ]; then
    missing "indexer password for ${INDEXER_ACCOUNT}, expected in INDEXER_PASSWORD"
elif ! printf '%s\n' "${INDEXER_PASSWORD}" | "${KEYSTORE}" -f indexer -k password > /dev/null 2>&1 \
        || ! printf '%s\n' "${INDEXER_ACCOUNT}" | "${KEYSTORE}" -f indexer -k username > /dev/null 2>&1; then
    missing "indexer password for ${INDEXER_ACCOUNT}, which the keystore refused"
else
    resolved "indexer password for ${INDEXER_ACCOUNT}"
fi

if [ -n "${MISSING}" ]; then
    echo "  The service was not started. To finish:"
    echo "      ${DOCUMENTATION}"

    if [ "${MODE}" = "--container" ]; then
        exit 1
    fi
fi

exit 0
