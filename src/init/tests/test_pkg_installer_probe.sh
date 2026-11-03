#!/bin/bash

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Drives the TCP fallback of probe_server() in pkg_installer.sh. probe_build_target() and
# probe_server() are cut out of the real script and sourced, and a stub curl exits 4 for --tlsv1.3,
# as the macOS system curl does, so every case takes the fallback. A local listener stands in for
# the manager.
#
#   ./test_pkg_installer_probe.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../pkg_installer.sh"

failures=0
checks=0

WORK="$(mktemp -d)"
LISTENER_PID=""
trap '[ -n "${LISTENER_PID}" ] && kill "${LISTENER_PID}" 2>/dev/null; rm -rf "${WORK}"' EXIT

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

sed -n '/^probe_build_target() {/,/^}/p;/^probe_server() {/,/^}/p' "${TARGET}" > "${WORK}/probe.sh"

mkdir -p "${WORK}/bin" "${WORK}/logs"
printf '#!/bin/sh\nfor arg in "$@"; do [ "${arg}" = "--tlsv1.3" ] && exit 4; done\nexit 0\n' > "${WORK}/bin/curl"
chmod +x "${WORK}/bin/curl"

python3 -c 'import socket, sys
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(16)
print(s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept(); c.close()' > "${WORK}/port" &
LISTENER_PID=$!
disown "${LISTENER_PID}"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "${WORK}/port" ] && break
    sleep 0.2
done
PORT="$(cat "${WORK}/port")"

# A port nothing listens on: bind one, then close it.
CLOSED_PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"

# $1 = host, $2 = port, $3 = shell code run before the probe, in the same shell.
probe() {
    ( cd "${WORK}" && PATH="${WORK}/bin:${PATH}" bash -c ". ./probe.sh; $3
      probe_server \"\$0\" \"\$1\" wazuh-manager; echo \$?" "$1" "$2" 2>/dev/null )
}

check "the fallback does not redirect onto a fixed fd" "" \
    "$(sed -n '/^probe_server() {/,/^}/p' "${TARGET}" | grep -E '[0-9]+<>[^&]*/dev/tcp')"

check "a reachable manager passes" "0" "$(probe 127.0.0.1 "${PORT}")"
check "the fallback is logged" "1" \
    "$(grep -c 'falling back to a TCP connectivity check' "${WORK}/logs/upgrade.log")"
check "a reachable manager named by host name passes" "0" "$(probe localhost "${PORT}")"
check "a reachable manager passes with fd 3 closed" "0" "$(probe localhost "${PORT}" 'exec 3<&-')"
check "a reachable manager passes with fd 3 already open" "0" \
    "$(probe localhost "${PORT}" 'exec 3</dev/null')"
check "a closed port fails" "1" "$(probe 127.0.0.1 "${CLOSED_PORT}")"
check "a name that does not resolve fails" "1" "$(probe no-such-host.invalid "${PORT}")"

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
