#!/bin/sh
# Docker healthcheck of a worker: healthy while every daemon a worker runs is up,
# that is all of them but apid, which runs on the master only.
out=$(/var/wazuh-manager/bin/wazuh-manager-control status) || true
[ -n "$out" ] || exit 1
! printf '%s\n' "$out" | grep -v '^wazuh-manager-apid ' | grep -qv ' is running'
