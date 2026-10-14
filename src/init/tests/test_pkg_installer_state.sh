#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives the end of pkg_installer.sh, where it waits for the upgraded agent to connect, against a
# throwaway install directory. A stub install.sh stands in for the package and curl, rpm and
# wazuh-control are stubs, so no manager or network is needed: each case chooses what
# var/run/wazuh-agentd.state holds.
#
#   ./test_pkg_installer_state.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../pkg_installer.sh"

failures=0
checks=0

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

LEGACY_CONF='<ossec_config>
  <client>
    <server>
      <address>127.0.0.1</address>
    </server>
  </client>
</ossec_config>
'

# A PATH holding the system's tools, and stubs for:
#   rpm   answers a 4.x agent version, so the TLS gate lets the upgrade through
#   curl  answers the connectivity check (-k) with 0 and the system-store check with 60
make_path() {

    local bin="$1"

    mkdir -p "${bin}"
    for tool in /usr/bin/* /bin/* /usr/sbin/* /sbin/*; do
        [ -x "${tool}" ] && [ ! -e "${bin}/$(basename "${tool}")" ] && ln -s "${tool}" "${bin}/" 2>/dev/null
    done
    rm -f "${bin}/curl" "${bin}/wget" "${bin}/rpm" "${bin}/dpkg-query"

    printf '#!/bin/sh\necho 4.14.7\n' > "${bin}/rpm"
    printf '#!/bin/sh\nfor arg in "$@"; do [ "${arg}" = "-k" ] && exit 0; done\nexit 60\n' > "${bin}/curl"
    chmod +x "${bin}/rpm" "${bin}/curl"

}

# Runs the target against a fresh tree, whose state file holds $2, and leaves it at ${WORK}/<case>.
run_case() {

    local name="$1" state="$2"
    local dir="${WORK}/${name}"

    mkdir -p "${dir}/etc" "${dir}/logs" "${dir}/bin" "${dir}/var/upgrade" "${dir}/var/incoming" "${dir}/var/run"
    printf '%s' "${LEGACY_CONF}" > "${dir}/etc/ossec.conf"
    printf '#!/bin/sh\nexit 0\n' > "${dir}/var/upgrade/install.sh"
    printf '#!/bin/sh\nexit 0\n' > "${dir}/bin/wazuh-control"
    chmod +x "${dir}/bin/wazuh-control"
    printf '%s' "${state}" > "${dir}/var/run/wazuh-agentd.state"
    make_path "${dir}/path"

    (cd "${dir}" && env -i PATH="${dir}/path" HOME="${dir}" INSTALLDIR="${dir}" bash "${TARGET}" > /dev/null 2>&1)

}

check() {

    local name="$1" expected="$2" actual="$3"

    checks=$(( checks + 1 ))
    if [ "${expected}" = "${actual}" ]; then
        echo "ok   - ${name}"
    else
        failures=$(( failures + 1 ))
        echo "FAIL - ${name}"
        echo "--- expected ---"
        echo "${expected}"
        echo "--- actual ---"
        echo "${actual}"
        echo "---"
    fi

}

log_count() {

    grep -c -E -- "$2" "${WORK}/$1/logs/upgrade.log"

}

present() {

    [ -e "${WORK}/$1/$2" ] && echo yes || echo no

}

# What wazuh-agentd writes (write_state(), src/client-agent/src/state.c).
CONNECTED_STATE="# State file for wazuh-agentd

# Agent status:
# - pending:      waiting to get connected.
# - connected:    connection established with manager in the last 10 seconds.
# - disconnected: connection lost or no ACK received in the last 60 seconds.
status='connected'

# Last time a keepalive was sent
last_keepalive='2026-10-14 10:00:00'
"

run_case connected "${CONNECTED_STATE}"
check "a connected agent finishes the upgrade" "1" "$(log_count connected "Upgrade finished successfully")"
check "the status read from the state file is logged" "1" "$(log_count connected "Status = connected")"
check "the upgrade result is 0" "0" "$(cat "${WORK}/connected/var/upgrade/upgrade_result" 2>/dev/null)"

# var/run is writable by the wazuh group: the file is read as data, so nothing in it runs as root.
run_case planted "touch ./planted-ran
${CONNECTED_STATE}"
check "a command in the state file is not run" "no" "$(present planted planted-ran)"
check "the status still reads from a file carrying other lines" "1" "$(log_count planted "Upgrade finished successfully")"

run_case planted_status "status='connected'; touch ./planted-ran
${CONNECTED_STATE}"
check "a command after the status is not run" "no" "$(present planted_status planted-ran)"

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
