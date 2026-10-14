#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Bring the e2e cluster workers up or down. They are their own compose project
# (dev-env-cluster, docker-compose.yml next to this script) on the base stack's
# network, so neither command can recreate or remove the indexer or dashboard.
#
#   up [-n N]   write the two secret files, publish one set of ports per worker,
#               start N workers (default 1), wait until healthy and print which
#               host ports reach which worker
#   ports       print that table again
#   down        remove the workers and delete the secret files
#
# Secrets: the cluster key comes from cluster/.env (written by init.sh and
# setup-master.sh, the master's source of truth) and the indexer password is
# WAZUH_INDEXER_MANAGER_PASSWORD from ../.credentials.env (the only key the worker
# needs out of the five there). Each goes to a 0600 file under cluster/.secrets/
# that compose mounts as a secret; neither value is printed, passed on a command
# line or put in the container's environment.
# ------------------------------------------------------------------------------
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
E2E_DIR=$(dirname "$SCRIPT_DIR")
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
ENV_FILE="${SCRIPT_DIR}/.env"
CREDENTIALS_FILE="${WAZUH_E2E_CREDENTIALS:-${E2E_DIR}/.credentials.env}"
SECRETS_DIR="${SCRIPT_DIR}/.secrets"
NETWORK=dev-env-engine_default
INDEXER_CONTAINER=wazuh-indexer
SERVICE=wazuh-worker
# First host port of each listener's range (at most 9 workers, so the three ranges never
# overlap). Each worker takes one free port from each range, in creation order rather than by
# index; `cluster.sh ports` reads the actual bindings.
HTTPS_BASE="${WAZUH_WORKER_HTTPS_BASE:-15171}"
AGENT_BASE="${WAZUH_WORKER_AGENT_BASE:-15141}"
AUTHD_BASE="${WAZUH_WORKER_AUTHD_BASE:-15151}"
MAX_WORKERS=9

die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: $0 up [-n N] | ports | down

  up [-n N]   start N workers (default 1, at most ${MAX_WORKERS}) joined to the master on the host
  ports       print the host ports published by each running worker
  down        remove the workers (the indexer and dashboard are not part of this project)
EOF
}

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

# read_key <file> <KEY> → REPLY: the value after the FIRST '=' of the first
# KEY= line (the generated alphabet may contain '='); the file is never sourced.
read_key() {
  local line
  line="$(grep -m1 "^$2=" "$1" 2>/dev/null)" || return 1
  REPLY="${line#*=}"
  [[ -n "$REPLY" ]]
}

# Same precedence as init.sh and setup-master.sh: an exported value wins (they
# store it into cluster/.env too), else the stored one. No default here: a key
# made up now would not be the master's.
cluster_setting() {  # cluster_setting <VAR> → REPLY
  if [[ -n "${!1:-}" ]]; then REPLY="${!1}"; return 0; fi
  read_key "$ENV_FILE" "$1" || die "$1 is not in ${ENV_FILE}: run ./cluster/init.sh and sudo ./cluster/setup-master.sh first"
}

write_secret() {  # write_secret <name> <value>
  ( umask 077; printf '%s' "$2" > "${SECRETS_DIR}/$1.new" )
  mv "${SECRETS_DIR}/$1.new" "${SECRETS_DIR}/$1"
}

port_range() {  # port_range <base> <n>
  if [[ $2 -eq 1 ]]; then echo "$1"; else echo "$1-$(( $1 + $2 - 1 ))"; fi
}

print_ports() {
  local ids id name https agent authd
  ids="$(compose ps -q "$SERVICE" 2>/dev/null)" || true
  [[ -n "$ids" ]] || { echo "No worker is running in project dev-env-cluster."; return 0; }
  printf '%-34s %-14s %-11s %-11s %-11s\n' CONTAINER NODE_NAME HTTPS:1517 AGENT:1514 AUTHD:1515
  for id in $ids; do
    name="$(docker inspect -f '{{.Name}}' "$id")"; name="${name#/}"
    # node_name is the container's hostname (node/entrypoint.sh).
    https="$(docker port "$id" 1517/tcp | head -n1)"; https="${https##*:}"
    agent="$(docker port "$id" 1514/tcp | head -n1)"; agent="${agent##*:}"
    authd="$(docker port "$id" 1515/tcp | head -n1)"; authd="${authd##*:}"
    printf '%-34s %-14s %-11s %-11s %-11s\n' "$name" "$(docker inspect -f '{{.Config.Hostname}}' "$id")" "$https" "$agent" "$authd"
  done
  cat <<EOF

Pin a 5.x agent to a worker: mint the token on the MASTER with that worker's HTTPS port,
  sudo ${E2E_DIR}/agents/create_token.sh --env-file <scratch>/agents.env --address host.docker.internal --port <HTTPS>
then start the agent with that env file (see cluster/README.md).
EOF
}

cmd_up() {
  local n=1
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n|--workers) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; n=$2; shift 2 ;;
      *) usage >&2; exit 2 ;;
    esac
  done
  [[ "$n" =~ ^[1-9]$ ]] || die "-n must be between 1 and ${MAX_WORKERS}"

  command -v docker >/dev/null 2>&1 || die "docker not found"
  docker network inspect "$NETWORK" >/dev/null 2>&1 \
    || die "network ${NETWORK} not found: start the base stack first (cd ${E2E_DIR} && docker compose up -d)"
  [[ "$(docker inspect -f '{{.State.Running}}' "$INDEXER_CONTAINER" 2>/dev/null)" == true ]] \
    || die "container ${INDEXER_CONTAINER} is not running: start the base stack first (cd ${E2E_DIR} && docker compose up -d)"
  compgen -G "${SCRIPT_DIR}/node/pkg/*.deb" >/dev/null || [[ -f "${SCRIPT_DIR}/node/pkg/wazuh-manager-tree.tar.gz" ]] \
    || die "no worker manager artifact in node/pkg: run ./cluster/init.sh first"

  local key name password
  cluster_setting WAZUH_CLUSTER_KEY; key="$REPLY"
  cluster_setting WAZUH_CLUSTER_NAME; name="$REPLY"
  [[ -f "$CREDENTIALS_FILE" ]] || die "${CREDENTIALS_FILE} not found: run ${E2E_DIR}/init.sh (it generates the e2e credentials)"
  read_key "$CREDENTIALS_FILE" WAZUH_INDEXER_MANAGER_PASSWORD \
    || die "WAZUH_INDEXER_MANAGER_PASSWORD is not in ${CREDENTIALS_FILE}"
  password="$REPLY"

  ( umask 077; mkdir -p "$SECRETS_DIR" ); chmod 700 "$SECRETS_DIR"
  write_secret cluster_key "$key"
  write_secret indexer_password "$password"
  unset key password REPLY
  echo "==> Secrets written to ${SECRETS_DIR}/ (0600): cluster_key, indexer_password"

  export WAZUH_CLUSTER_NAME="$name"
  export WAZUH_WORKER_HTTPS_PORTS WAZUH_WORKER_AGENT_PORTS WAZUH_WORKER_AUTHD_PORTS
  WAZUH_WORKER_HTTPS_PORTS="$(port_range "$HTTPS_BASE" "$n")"
  WAZUH_WORKER_AGENT_PORTS="$(port_range "$AGENT_BASE" "$n")"
  WAZUH_WORKER_AUTHD_PORTS="$(port_range "$AUTHD_BASE" "$n")"
  echo "==> Starting ${n} worker(s) of cluster '${name}' (host ports: HTTPS ${WAZUH_WORKER_HTTPS_PORTS}, agent ${WAZUH_WORKER_AGENT_PORTS}, authd ${WAZUH_WORKER_AUTHD_PORTS})"
  compose up -d --build --scale "${SERVICE}=${n}" --wait --wait-timeout 300
  echo
  print_ports
}

cmd_down() {
  # The cluster name is only needed to parse the file, not to remove.
  WAZUH_CLUSTER_NAME=unused compose down --remove-orphans
  rm -rf "$SECRETS_DIR"
  echo "==> Workers removed; ${SECRETS_DIR}/ deleted. The indexer and dashboard were not touched."
}

case "${1:-}" in
  up)    shift; cmd_up "$@" ;;
  ports) WAZUH_CLUSTER_NAME=unused print_ports ;;
  down)  cmd_down ;;
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
