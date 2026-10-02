#!/bin/bash
set -e

CONFIG_FILE="/etc/wazuh-indexer/opensearch.yml"

# ----------------------------------------------------------------------------
# Credentials coherence (FIRST, before the certs are copied: --clear also
# removes the pem files under /etc/wazuh-indexer/certs).
#
# The image ships no credentials (Dockerfile: --clear + pristine
# internal_users.yml + no credentials.env); the passwords come from the env
# (env_file .credentials.env). The resolver's marker (.initialized) lives in the
# data volume and survives a recreation, while internal_users.yml and
# credentials.env do not -- so re-resolve whenever the container is new (no
# credentials.env) or the env passwords changed since the last resolution (a
# missing stored signature counts as changed). Only a SHA-256 of the KEY=value
# lines is stored; no value is ever printed.
# ----------------------------------------------------------------------------
RESOLVER="/usr/share/wazuh-indexer/bin/resolve-credentials.sh"
CREDS_SIG_FILE="/var/lib/wazuh-indexer/.e2e_creds.sig"
CREDS_MARKER="/var/lib/wazuh-indexer/.initialized"
CREDENTIALS_ENV="/etc/wazuh/credentials.env"

creds_sig() {
    local k lines=""
    for k in WAZUH_INDEXER_ADMIN_PASSWORD WAZUH_INDEXER_KIBANASERVER_PASSWORD WAZUH_INDEXER_MANAGER_PASSWORD; do
        if [ -n "${!k+x}" ]; then
            lines+="${k}=${!k}"$'\n'
        fi
    done
    if [ -z "${lines}" ]; then
        echo "none"
    else
        printf '%s' "${lines}" | LC_ALL=C sort | sha256sum | cut -d' ' -f1
    fi
}

CUR_CREDS_SIG="$(creds_sig)"
STORED_CREDS_SIG="$(cat "${CREDS_SIG_FILE}" 2>/dev/null || true)"

# The marker+signature disjunct is deliberate belt-and-braces: with the image
# shipping no credentials.env, every new container already enters through the
# second condition; the first one only fires if a future image change brings
# the file back or a volume carries a stale signature.
if { [ -f "${CREDS_MARKER}" ] && [ "${STORED_CREDS_SIG}" != "${CUR_CREDS_SIG}" ]; } \
   || [ ! -f "${CREDENTIALS_ENV}" ]; then
    echo "Credentials: new container or env passwords changed; clearing the resolved state..."
    if ! "${RESOLVER}" --clear; then
        echo "WARN: resolve-credentials.sh --clear failed; continuing with the previous state"
    fi
fi

if [ ! -f "${CREDENTIALS_ENV}" ] || [ ! -f "${CREDS_MARKER}" ]; then
    echo "Credentials: resolving from the environment (resolve-credentials.sh --prestart)..."
    "${RESOLVER}" --prestart || echo "WARN: credentials resolution failed (degraded)"
fi

mkdir -p "$(dirname "${CREDS_SIG_FILE}")"
( umask 077; printf '%s\n' "${CUR_CREDS_SIG}" > "${CREDS_SIG_FILE}" )
chmod 600 "${CREDS_SIG_FILE}"

# Wait for certificates to be mounted
echo "Checking for certificates..."

# Set correct ownership and permissions for certificates in /etc/wazuh-indexer/certs/
if [ -d "/etc/wazuh-indexer/certs" ]; then
    echo "Setting up certificate permissions..."
    cp /certs/node-1-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
    cp /certs/node-1.pem /etc/wazuh-indexer/certs/indexer.pem
    cp /certs/root-ca.pem /etc/wazuh-indexer/certs/root-ca.pem
    cp /certs/admin.pem /etc/wazuh-indexer/certs/admin.pem
    cp /certs/admin-key.pem /etc/wazuh-indexer/certs/admin-key.pem
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs/
    chmod 640 /etc/wazuh-indexer/certs/*
fi

# ----------------------------------------------------------------------------
# Align admin_dn / nodes_dn with the MOUNTED certificates.
#
# The credentials PR (indexer#1928) makes the package resolve TLS material at
# build time, so the image ships admin_dn / nodes_dn matching the certs it
# generated then (and nodes_dn carries the build host, e.g. CN=buildkitsandbox).
# This e2e stack mounts its own certs (CN=admin, CN=node-1) instead, so those
# baked DNs never match and securityadmin rejects the admin cert. Rewrite both
# keys from the DN the mounted certs actually present (RFC2253 order, which is
# what OpenSearch compares against) BEFORE the service reads opensearch.yml.
# ----------------------------------------------------------------------------
set_dn_list() {
    # $1 = yaml key (e.g. plugins.security.authcz.admin_dn), $2 = DN string.
    # awk only: the container ships no python3. Replaces the key's whole list
    # (every consecutive "- ..." entry), not just the first one.
    local key="$1" dn="$2"
    awk -v key="$key" -v dn="$dn" '
        $0 ~ "^"key":" { print; print "- \"" dn "\""; skip=1; next }
        skip==1 && /^[[:space:]]*-[[:space:]]/ { next }
        { skip=0; print }
    ' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}
if [ -f "/etc/wazuh-indexer/certs/admin.pem" ]; then
    ADMIN_DN="$(openssl x509 -in /etc/wazuh-indexer/certs/admin.pem -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
    NODE_DN="$(openssl x509 -in /etc/wazuh-indexer/certs/indexer.pem -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
    echo "Aligning admin_dn=${ADMIN_DN} nodes_dn=${NODE_DN} with the mounted certs..."
    set_dn_list "plugins.security.authcz.admin_dn" "$ADMIN_DN"
    set_dn_list "plugins.security.nodes_dn" "$NODE_DN"
fi

# ----------------------------------------------------------------------------
# D5: warn when the engine in the wazuh-indexer-engine volume is not the one
# this image's package installed (a named volume keeps the first image's copy
# across rebuilds). Warning only; it never blocks the start.
# ----------------------------------------------------------------------------
ENGINE_BIN="/usr/share/wazuh-indexer/engine/bin/wazuh-engine"
PKG_MD5SUMS="/var/lib/dpkg/info/wazuh-indexer.md5sums"
if [ -f "${ENGINE_BIN}" ] && [ -f "${PKG_MD5SUMS}" ]; then
    ENGINE_MD5="$(md5sum "${ENGINE_BIN}" 2>/dev/null | cut -d' ' -f1 || true)"
    PKG_ENGINE_MD5="$(awk '$2 == "usr/share/wazuh-indexer/engine/bin/wazuh-engine" { print $1 }' "${PKG_MD5SUMS}" 2>/dev/null || true)"
    if [ -n "${PKG_ENGINE_MD5}" ] && [ "${ENGINE_MD5}" != "${PKG_ENGINE_MD5}" ]; then
        echo "WARNING: engine volume drift: ${ENGINE_BIN} differs from the installed package's copy."
        echo "WARNING: to pick up the image's engine: docker compose down && docker volume rm <project>_wazuh-indexer-engine (e.g. dev-env-engine_wazuh-indexer-engine)"
    fi
fi

# Start wazuh-indexer service
echo "Starting wazuh-indexer..."
service wazuh-indexer start

# Wait for service to be ready
echo "Waiting for wazuh-indexer to be ready..."
sleep 3

# Check if server is up 'service wazuh-indexer status' (evaluated inside the
# if, so a failed status does not abort under set -e before the restart)
if ! service wazuh-indexer status; then
    echo "Wazuh-indexer service failed to start."
    service wazuh-indexer restart || true
    sleep 3
    if ! service wazuh-indexer status; then
        echo "Wazuh-indexer service failed to start after restart. Exiting."
        exit 1
    fi
fi


# ----------------------------------------------------------------------------
# Apply the generated credentials to the live security index.
#
# The coherence block above runs resolve-credentials.sh, which takes one password
# per account (admin, kibanaserver, wazuh-manager) from the env, writes their
# bcrypt hashes into internal_users.yml and publishes the plaintext into
# /etc/wazuh/credentials.env. Loading those hashes into the running security
# index still requires securityadmin (indexer-security-init.sh).
#
# Keyed on the CONTENT of internal_users.yml so it re-applies whenever the
# shipped hashes change (a new package or rotated credentials) and is skipped
# otherwise, preserving a post-install rotation across restarts. Non-fatal: a
# securityadmin failure must not take the container down -- the index simply
# keeps whatever credentials it already had.
# ----------------------------------------------------------------------------
INIT_DIR="/etc/wazuh-indexer-init"
INTERNAL_USERS="/etc/wazuh-indexer/opensearch-security/internal_users.yml"
SIG_FILE="${INIT_DIR}/.security_applied.sig"
mkdir -p "${INIT_DIR}"
CUR_SIG="$(sha256sum "${INTERNAL_USERS}" 2>/dev/null | cut -d' ' -f1)"
# Wait for the cluster REST layer before pushing (a push during cluster formation
# can leave the in-memory security config stale even when securityadmin reports
# success), then verify a real basic-auth login and retry the push once: the
# second push also flushes the plugin's auth cache, which may hold the failed
# attempts made while the old hashes were still live.
wait_cluster() {
    # Waits for a REAL 200 from _cluster/health (client-cert auth): during
    # cluster formation the TLS port already answers with 503, which is not
    # enough to push the security config.
    local i code
    for i in $(seq 1 30); do
        code=$(curl -sk --cert /etc/wazuh-indexer/certs/admin.pem --key /etc/wazuh-indexer/certs/admin-key.pem \
             -o /dev/null -w '%{http_code}' https://127.0.0.1:9200/_cluster/health 2>/dev/null)
        [ "$code" = 200 ] && return 0
        sleep 3
    done
    return 1
}
auth_probe() {
    # rc 0 = EVERY account published in credentials.env authenticates (200).
    # The race this guards against left admin broken while kibanaserver worked,
    # so probing one account is not enough. Vacuous success is not success:
    # a missing file or no published key WARNs and returns 1 (the signature is
    # then not recorded and the next start retries). Never prints a value.
    local l k v u cfg rc found=0
    if [ ! -f /etc/wazuh/credentials.env ]; then
        echo "WARN: auth probe: /etc/wazuh/credentials.env missing (resolution failed?)"
        return 1
    fi
    while IFS= read -r l; do
        case "$l" in
            WAZUH_INDEXER_ADMIN_PASSWORD=*)        u=admin;;
            WAZUH_INDEXER_KIBANASERVER_PASSWORD=*) u=kibanaserver;;
            WAZUH_INDEXER_MANAGER_PASSWORD=*)      u=wazuh-manager;;
            *) continue;;
        esac
        v=${l#*=}; v=${v%\"}; v=${v#\"}
        [ -n "$v" ] || continue
        found=1
        cfg=$(mktemp); chmod 600 "$cfg"; printf 'user = "%s:%s"\n' "$u" "$v" > "$cfg"
        rc=$(curl -sk -K "$cfg" -o /dev/null -w '%{http_code}' https://127.0.0.1:9200)
        rm -f "$cfg"
        if [ "$rc" != 200 ]; then
            echo "WARN: auth probe: ${u} does not authenticate (HTTP ${rc})"
            return 1
        fi
    done < /etc/wazuh/credentials.env
    if [ "$found" = 0 ]; then
        echo "WARN: auth probe: no published indexer key found in credentials.env"
        return 1
    fi
    return 0
}
if [ ! -f "${SIG_FILE}" ] || [ "$(cat "${SIG_FILE}" 2>/dev/null)" != "${CUR_SIG}" ]; then
    echo "Applying generated credentials to the security index (internal_users.yml changed)..."
    wait_cluster || echo "WARNING: cluster not reachable after 90s; trying securityadmin anyway."
    if /usr/share/wazuh-indexer/bin/indexer-security-init.sh; then
        if ! auth_probe; then
            echo "Auth probe failed after the first push; re-applying (flushes the auth cache)..."
            sleep 5
            /usr/share/wazuh-indexer/bin/indexer-security-init.sh || true
        fi
        if auth_probe; then
            echo "${CUR_SIG}" > "${SIG_FILE}"
            echo "Security configuration applied and verified; signature recorded."
        else
            echo "WARNING: securityadmin ran but the auth probe still fails; signature NOT recorded (will retry next start)."
        fi
    else
        echo "WARNING: securityadmin failed; the security index keeps its previous credentials."
    fi
else
    echo "Security already applied for the current internal_users.yml; skipping."
fi

echo "Wazuh-indexer is ready!"


# Keep container running - if CMD was provided, execute it, otherwise keep alive
if [ "$#" -gt 0 ] && [ "$1" != "/bin/bash" ]; then
    exec "$@"
else
    tail -f /dev/null
fi
