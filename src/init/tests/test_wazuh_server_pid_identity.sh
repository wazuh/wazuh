#!/bin/sh

# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU
# General Public License (version 2) as published by the FSF - Free Software Foundation.

# Exercises wazuh-manager-control against a throwaway installation tree. The fake manager
# configuration reader keeps status self-contained, while copies of sleep provide live processes
# with deterministic Linux comm names.
#
#   sh src/init/tests/test_wazuh_server_pid_identity.sh

REPO=$(cd "$(dirname "$0")/../../.." && pwd)
TARGET="${REPO}/src/init/wazuh-server.sh"
WORK=$(mktemp -d)
PIDS=""

cleanup() {
    for pid in ${PIDS}; do
        kill "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    done
    rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "FAIL - $1" >&2
    exit 1
}

assert_contains() {
    case "$1" in
        *"$2"*) ;;
        *) fail "$3: expected '$2' in output: $1" ;;
    esac
}

HOME_DIR="${WORK}/manager"
mkdir -p "${HOME_DIR}/bin" "${HOME_DIR}/var/run"
cp "${TARGET}" "${HOME_DIR}/bin/wazuh-control"
chmod +x "${HOME_DIR}/bin/wazuh-control"

cat > "${HOME_DIR}/bin/wazuh-manager-conf" <<'EOF'
#!/bin/sh
case "$*" in
    *"get cluster.node_type"*) echo master ;;
    *"get auth.disabled"*) echo false ;;
esac
exit 0
EOF
chmod +x "${HOME_DIR}/bin/wazuh-manager-conf"

# A live sibling daemon must not satisfy remoted's pidfile.
cp /bin/sleep "${HOME_DIR}/bin/wazuh-manager-maild"
"${HOME_DIR}/bin/wazuh-manager-maild" 60 &
maild_pid=$!
PIDS="${PIDS} ${maild_pid}"
printf '%s\n' "${maild_pid}" > \
    "${HOME_DIR}/var/run/wazuh-manager-remoted-${maild_pid}.pid"

status_output=$("${HOME_DIR}/bin/wazuh-control" status 2>&1) || true
assert_contains "${status_output}" "wazuh-manager-remoted not running..." \
    "sibling daemon collision"
[ ! -e "${HOME_DIR}/var/run/wazuh-manager-remoted-${maild_pid}.pid" ] || \
    fail "sibling daemon collision: stale pidfile was not removed"
kill -0 "${maild_pid}" 2>/dev/null || \
    fail "sibling daemon collision: the sibling process was signalled"

# Linux comm names are limited to 15 bytes. The matching long daemon name must still be accepted.
cp /bin/sleep "${HOME_DIR}/bin/wazuh-manager-remoted"
"${HOME_DIR}/bin/wazuh-manager-remoted" 60 &
remoted_pid=$!
PIDS="${PIDS} ${remoted_pid}"
printf '%s\n' "${remoted_pid}" > \
    "${HOME_DIR}/var/run/wazuh-manager-remoted-${remoted_pid}.pid"

status_output=$("${HOME_DIR}/bin/wazuh-control" status 2>&1) || true
assert_contains "${status_output}" "wazuh-manager-remoted is running..." \
    "matching daemon identity"
[ -e "${HOME_DIR}/var/run/wazuh-manager-remoted-${remoted_pid}.pid" ] || \
    fail "matching daemon identity: live pidfile was removed"

echo "ok - wazuh-manager-remoted PID identity"
