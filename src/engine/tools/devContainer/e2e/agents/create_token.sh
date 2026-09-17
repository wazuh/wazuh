#!/usr/bin/env bash
# create_token.sh — mint an enrollment token on the local manager and write the credentials the
# containerised agents need into an env file for `docker compose --env-file`:
#   WAZUH_ENROLLMENT_TOKEN=…   5.x agents: POST /enroll with a wazuh-enroll+jwt bearer (kid = token id),
#                              after bootstrapping trust from GET /cacerts against the token's pin
#   AUTHD_PASSWORD=…           4.x agents: agent-auth -P against authd (the manager ships use_password=yes)
#
# The token is printed ONCE by the CLI on stdout and goes only into the env file (0600). Its id,
# endpoint, expiry and pin (stderr of the CLI) go to --meta; nothing here prints the token or the
# password. Minting is master-only and needs authd running (it is a client of queue/sockets/auth.sock);
# --address must be a SAN of the listener certificate — host.docker.internal is one in the devcontainer
# (scripts/wazuh-certs-tool.yml). Reference: docs/ref/modules/authd/README.md#enrollment-tokens.
set -u

usage() {
  cat <<EOF
Usage: sudo $0 --env-file PATH [--meta PATH] [--address HOST] [--port N] [--prefix P] [--ttl 1d]
               [--max-uses N] [--description S] [--embed-ca] [--no-password] [--home DIR] [-h|--help]

  --env-file PATH   where to write WAZUH_ENROLLMENT_TOKEN= and AUTHD_PASSWORD= (created 0600; required)
  --meta PATH       where to write the token metadata (id, endpoint, expiry, pin — never the token)
  --address HOST    the listener name the agents connect to (default host.docker.internal; must be a SAN)
  --port N          only when the HTTPS listener is not on 1517 (the default is elided from the token)
  --prefix P        only when remote.https.global_prefix is not wazuh-manager (idem)
  --ttl 1d          token lifetime, N[d|h|m|s] (default 1d; the CLI default is 30d)
  --max-uses N      how many agents may enroll with it (default unlimited; set it to the number of agents)
  --description S   free text stored with the token (default "e2e agents <date>")
  --embed-ca        carry the CA inside the token instead of its pin (the agent then skips GET /cacerts)
  --no-password     do not add AUTHD_PASSWORD (4.x agents will not be able to enroll)
  --home DIR        installed manager (default /var/wazuh-manager, or WAZUH_MANAGER_HOME)
EOF
}

HOME_DIR="${WAZUH_MANAGER_HOME:-/var/wazuh-manager}"
ENV_FILE=""; META=""; ADDRESS="host.docker.internal"; PORT=""; PREFIX=""; TTL="1d"; MAX_USES=""
DESC=""; EMBED_CA=0; NO_PASSWORD=0
while [ $# -gt 0 ]; do
  case "$1" in
    --env-file) ENV_FILE=$2; shift 2 ;;
    --meta) META=$2; shift 2 ;;
    --address) ADDRESS=$2; shift 2 ;;
    --port) PORT=$2; shift 2 ;;
    --prefix) PREFIX=$2; shift 2 ;;
    --ttl) TTL=$2; shift 2 ;;
    --max-uses) MAX_USES=$2; shift 2 ;;
    --description) DESC=$2; shift 2 ;;
    --embed-ca) EMBED_CA=1; shift ;;
    --no-password) NO_PASSWORD=1; shift ;;
    --home) HOME_DIR=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }
[ -n "$ENV_FILE" ] || { usage >&2; die "--env-file is required"; }
[ "$(id -u)" -eq 0 ] || die "run as root (the CLI talks to the manager's local socket and authd.pass is not world-readable)"
AUTHD="$HOME_DIR/bin/wazuh-manager-authd"
[ -x "$AUTHD" ] || die "no manager at $HOME_DIR ($AUTHD missing)"
"$HOME_DIR/bin/wazuh-manager-control" status 2>/dev/null | grep -q 'wazuh-manager-authd is running' \
  || die "wazuh-manager-authd is not running — minting is a client of queue/sockets/auth.sock (start the manager first)"

DESC="${DESC:-e2e agents $(date -u +%Y-%m-%dT%H:%MZ)}"
declare -a ARGS=(--create-enrollment-token --address "$ADDRESS" --ttl "$TTL" --description "$DESC")
[ -z "$PORT" ] || ARGS+=(--port "$PORT")
[ -z "$PREFIX" ] || ARGS+=(--prefix "$PREFIX")
[ -z "$MAX_USES" ] || ARGS+=(--max-uses "$MAX_USES")
[ "$EMBED_CA" -eq 0 ] || ARGS+=(--embed-ca)

err_tmp=$(mktemp)
trap 'rm -f "$err_tmp"' EXIT
token=$("$AUTHD" "${ARGS[@]}" 2>"$err_tmp")
rc=$?
if [ "$rc" -ne 0 ] || [ -z "$token" ]; then
  echo "ERROR: the CLI refused the mint (rc=$rc):" >&2
  sed 's/^/    /' "$err_tmp" >&2
  exit 1
fi

# The env file: token (+ the manager's shared password for the 4.x agents), 0600, never printed.
umask 077
mkdir -p "$(dirname "$ENV_FILE")"
{
  echo "# written by create_token.sh $(date -u +%Y-%m-%dT%H:%M:%SZ) — delete after 'docker compose up'"
  echo "WAZUH_ENROLLMENT_TOKEN=$token"
  if [ "$NO_PASSWORD" -eq 0 ] && [ -r "$HOME_DIR/etc/authd.pass" ]; then
    echo "AUTHD_PASSWORD=$(head -n 1 "$HOME_DIR/etc/authd.pass" | tr -d '\r\n')"
  fi
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"

# Metadata: whatever the CLI reported on stderr (id, endpoint, expiry, pin), minus any line that
# could carry the token itself, plus what was asked for.
meta_lines=$(grep -vF -- "$token" "$err_tmp" | sed 's/^[[:space:]]*//')
if [ -n "$META" ]; then
  mkdir -p "$(dirname "$META")"
  {
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "address=$ADDRESS${PORT:+ port=$PORT}${PREFIX:+ prefix=$PREFIX}"
    echo "ttl=$TTL max_uses=${MAX_USES:-unlimited} embed_ca=$EMBED_CA"
    echo "description=$DESC"
    echo "env_file=$ENV_FILE"
    echo "password_included=$([ "$NO_PASSWORD" -eq 0 ] && [ -r "$HOME_DIR/etc/authd.pass" ] && echo yes || echo no)"
    echo "--- wazuh-manager-authd stderr ---"
    printf '%s\n' "$meta_lines"
  } > "$META"
fi

echo "# create_token.sh — token minted on $HOME_DIR for address=$ADDRESS ttl=$TTL max_uses=${MAX_USES:-unlimited}"
printf '%s\n' "$meta_lines" | sed 's/^/    /'
echo "# env file: $ENV_FILE (0600; WAZUH_ENROLLMENT_TOKEN$([ "$NO_PASSWORD" -eq 0 ] && echo ' + AUTHD_PASSWORD'))"
[ -z "$META" ] || echo "# meta: $META"
echo "# next: docker compose --env-file $ENV_FILE -f $(dirname "$0")/docker-compose.yml up -d --build [service…]"
echo "#       then delete the env file; revoke with: $AUTHD --revoke-enrollment-token <id>"
