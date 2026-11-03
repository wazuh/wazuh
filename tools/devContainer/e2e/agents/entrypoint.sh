#!/usr/bin/env bash
# entrypoint.sh — configure and start a containerised Wazuh agent against the devcontainer's manager.
#
# 4.x (the package ships bin/agent-auth): <client><server> address/port from MANAGER_HOST/MANAGER_PORT,
#      enrollment through authd on AUTHD_PORT with the shared password AUTHD_PASSWORD — the manager
#      ships <auth><use_password>yes</use_password>, so without it authd answers "Invalid password".
# 5.x (no agent-auth in the package): enrollment ONLY through POST /enroll on the HTTPS listener with
#      an enrollment token (WAZUH_ENROLLMENT_TOKEN, minted on the manager by create_token.sh). The
#      packaged register_configure_agent.sh is the official implementation: it decodes the token with
#      `wazuh-agentd --show-token`, replaces <agent><manager> by <endpoint>ADR</endpoint> (the token
#      carries host[:port][/prefix]), sets <enrollment><agent_name>, and stores the token in
#      etc/enrollment_token (0600 root). wazuh-agentd then bootstraps before dropping privileges:
#      GET /cacerts → pin check → POST /enroll → the token file is unlinked. Port 1515 is never used.
# A volume that already holds a key (non-empty etc/client.keys) is started as is; reset with
# `docker compose down -v`.
set -euo pipefail

MANAGER_HOST="${MANAGER_HOST:-host.docker.internal}"
MANAGER_PORT="${MANAGER_PORT:-1514}"
AUTHD_PORT="${AUTHD_PORT:-1515}"
AGENT_NAME="${AGENT_NAME:-$(hostname)}"
AUTHD_PASSWORD="${AUTHD_PASSWORD:-}"
WAZUH_ENROLLMENT_TOKEN="${WAZUH_ENROLLMENT_TOKEN:-}"

OSSEC_DIR=/var/ossec
OSSEC_CONF="$OSSEC_DIR/etc/ossec.conf"
LOG_FILE="$OSSEC_DIR/logs/ossec.log"
KEYS="$OSSEC_DIR/etc/client.keys"
REGISTER_SCRIPT=$(ls "$OSSEC_DIR"/packages_files/agent_installation_scripts/src/init/register_configure_agent.sh 2>/dev/null | head -1 || true)

log() { echo "[entrypoint] $*"; }

if [ -x "$OSSEC_DIR/bin/agent-auth" ]; then FLAVOUR=4.x; else FLAVOUR=5.x; fi
log "flavour=$FLAVOUR agent_name=$AGENT_NAME"

if [ -s "$KEYS" ]; then
  log "etc/client.keys already holds a key: starting without re-enrolling (docker compose down -v resets the volume)"
else
  case "$FLAVOUR" in
    4.x)
      log "manager=${MANAGER_HOST}:${MANAGER_PORT} authd=${MANAGER_HOST}:${AUTHD_PORT}"
      sed -i "s|<address>.*</address>|<address>${MANAGER_HOST}</address>|" "$OSSEC_CONF"
      # Restricted to <client>: the file carries unrelated <port> tags elsewhere.
      sed -i "/<client>/,/<\/client>/ s|<port>.*</port>|<port>${MANAGER_PORT}</port>|" "$OSSEC_CONF"
      if [ -z "$AUTHD_PASSWORD" ]; then
        log "WARN: AUTHD_PASSWORD is empty — authd refuses the request while the manager has <use_password>yes (create_token.sh writes it into the compose env file)"
      fi
      # agent-auth's exit status is the verdict: a failure is reported, never swallowed silently.
      if ! "$OSSEC_DIR/bin/agent-auth" -A "$AGENT_NAME" -m "$MANAGER_HOST" -p "$AUTHD_PORT" ${AUTHD_PASSWORD:+-P "$AUTHD_PASSWORD"}; then
        log "ERROR: agent-auth failed — the agent starts unenrolled; look for 'Invalid password' / 'Duplicate name' in the manager log"
      fi
      ;;
    5.x)
      if [ -z "$WAZUH_ENROLLMENT_TOKEN" ]; then
        log "ERROR: WAZUH_ENROLLMENT_TOKEN is empty. A 5.x agent enrolls only through POST /enroll with an enrollment token"
        log "       minted on the manager (agents/create_token.sh writes the compose env file). Refusing to start unenrolled."
        exit 78
      fi
      # The packaged installer script is the official implementation, but the postinst removes
      # /var/ossec/packages_files after the install, so it is normally absent at container start:
      # apply the same three effects here (endpoint from the token, agent name, token file).
      if [ -n "$REGISTER_SCRIPT" ]; then
        log "applying the token with the packaged register_configure_agent.sh"
        if ! WAZUH_ENROLLMENT_TOKEN="$WAZUH_ENROLLMENT_TOKEN" WAZUH_AGENT_NAME="$AGENT_NAME" bash "$REGISTER_SCRIPT" "$OSSEC_DIR"; then
          log "ERROR: register_configure_agent.sh refused the deployment variables — see 'Deployment variables refused [...]' in $LOG_FILE"
          exit 78
        fi
      else
        # --show-token prints a description without the credential; 'adr' is host[:port][/prefix]
        # (the defaults 1517 and wazuh-manager are elided from the token and re-added by the agent).
        if ! description=$(printf '%s' "$WAZUH_ENROLLMENT_TOKEN" | "$OSSEC_DIR/bin/wazuh-agentd" --show-token 2>&1); then
          log "ERROR: wazuh-agentd --show-token refused the token: $description"
          exit 78
        fi
        adr=$(printf '%s\n' "$description" | sed -n 's/^adr: //p')
        if [ -z "$adr" ]; then
          log "ERROR: the token carries no address (adr); refusing to start unenrolled"
          exit 78
        fi
        # <agent><manager><endpoint> is the only address the 5.x parser reads; the shipped file has
        # the MANAGER_IP placeholder there. <enrollment><agent_name> names the agent at /enroll.
        sed -i "/<manager>/,/<\/manager>/ s|<endpoint>.*</endpoint>|<endpoint>${adr}</endpoint>|" "$OSSEC_CONF"
        if grep -q "<enrollment>" "$OSSEC_CONF"; then
          sed -i "/<enrollment>/,/<\/enrollment>/ s|<agent_name>.*</agent_name>|<agent_name>${AGENT_NAME}</agent_name>|" "$OSSEC_CONF"
        else
          sed -i "s|</manager>|</manager>\n    <enrollment>\n      <agent_name>${AGENT_NAME}</agent_name>\n    </enrollment>|" "$OSSEC_CONF"
        fi
        # Root-only, unlike authd.pass: wazuh-agentd reads it before dropping privileges and
        # unlinks it once the bootstrap succeeded.
        umask 077
        printf '%s' "$WAZUH_ENROLLMENT_TOKEN" > "$OSSEC_DIR/etc/enrollment_token"
        chown root:root "$OSSEC_DIR/etc/enrollment_token"
        chmod 600 "$OSSEC_DIR/etc/enrollment_token"
      fi
      endpoint=$(sed -n 's|.*<endpoint>\(.*\)</endpoint>.*|\1|p' "$OSSEC_CONF" | head -1)
      token_file=$([ -f "$OSSEC_DIR/etc/enrollment_token" ] && echo present || echo missing)
      log "token applied: endpoint=${endpoint:-?} enrollment_token=${token_file} (wazuh-agentd fetches GET /cacerts, checks the pin and POSTs /enroll at start)"
      ;;
  esac
fi

"$OSSEC_DIR/bin/wazuh-control" start
touch "$LOG_FILE"
exec tail -F "$LOG_FILE"
