#!/usr/bin/env bash
set -euo pipefail

MANAGER_HOST="${MANAGER_HOST:-host.docker.internal}"
MANAGER_PORT="${MANAGER_PORT:-1514}"
AUTHD_PORT="${AUTHD_PORT:-1515}"
AGENT_NAME="${AGENT_NAME:-$(hostname)}"
AUTHD_PASSWORD="${AUTHD_PASSWORD:-}"

OSSEC_CONF="/var/ossec/etc/ossec.conf"
LOG_FILE="/var/ossec/logs/ossec.log"

echo "[entrypoint] manager=${MANAGER_HOST}:${MANAGER_PORT} authd_port=${AUTHD_PORT} agent_name=${AGENT_NAME}"

if grep -q "<address>" "$OSSEC_CONF"; then
  sed -i "s|<address>.*</address>|<address>${MANAGER_HOST}</address>|" "$OSSEC_CONF" || true
else
  echo "[entrypoint] WARN: <address> tag not found in ${OSSEC_CONF}."
fi

if [[ -n "${AUTHD_PASSWORD}" ]]; then
  /var/ossec/bin/agent-auth -A "${AGENT_NAME}" -m "${MANAGER_HOST}" -p "${AUTHD_PORT}" -P "${AUTHD_PASSWORD}" || true
else
  /var/ossec/bin/agent-auth -A "${AGENT_NAME}" -m "${MANAGER_HOST}" -p "${AUTHD_PORT}" || true
fi

/var/ossec/bin/wazuh-control start

touch "$LOG_FILE"
tail -F "$LOG_FILE"
