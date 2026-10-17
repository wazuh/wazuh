#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# wazuh_copy_certs.sh - deploy the E2E certificates into a wazuh-manager install
#
# Usage: sudo ./wazuh_copy_certs.sh
#
# Copies the files issued by ./init.sh (scripts/wazuh-certs-tool.sh) from certs/
# into /etc/wazuh-manager/certs (root:wazuh-manager 0750) with the ownership the
# installer expects:
#
#   root-ca.pem             -> root-ca.pem                 root:wazuh-manager  640
#   root-ca.pem             -> indexer-ca.pem              root:wazuh-manager  640
#   <node>.pem              -> indexer-connector.pem       root:wazuh-manager  640
#   <node>-key.pem          -> indexer-connector-key.pem   root:wazuh-manager  640
#   <node>-remoted.pem      -> remoted.pem                 root:wazuh-manager  640
#   <node>-remoted-key.pem  -> remoted-key.pem             root:wazuh-manager  640
#   <node>-remoted.pem      -> apid.pem                    root:wazuh-manager  640
#   <node>-remoted-key.pem  -> apid-key.pem                root:wazuh-manager  640
#
# The Server API pair is the listener pair: the installer issues apid.pem with the
# profile of remoted.pem, and the e2e reaches the API on localhost, which its SAN carries.
#
# The e2e indexer's certificates come from the same CA, so it is also the indexer
# CA, and the manager node's certificate (issued with clientAuth) is the indexer
# client pair.
#
# Every daemon opens its pair after dropping privileges, through the group: the
# files stay root-owned so the service user can read them but never rewrite them.
# wazuh-manager.conf is NOT edited: the <remote><https> defaults already point at
# these paths (the block is printed for review).
#
# The installation minted a CA of its own in /etc/wazuh-manager/ca. These pairs
# come from the e2e CA, so that CA is replaced by the e2e CA's certificate alone
# (root:root 644 in a root:root 700 ca/): the credential resolver checks at every
# start that the Server API pair chains to it, and with no key beside it nothing
# can be issued on this node. root-ca.key is never copied; it only signs, here, the dashboard
# client pair published in export/ (CN=wazuh-dashboard, clientAuth), which replaces the one the
# installation issued from its own CA. Then
# wazuh-manager-resolve-credentials --install publishes the new CA in
# export/ca.pem, and --check confirms the start will find nothing to refuse.
#
# Environment:
#   WAZUH_MANAGER_HOME  manager install directory (default: /var/wazuh-manager); the
#                       configuration directory is always /etc/wazuh-manager
#   MANAGER_NODE_NAME   <node> above (default: first "- name:" under "manager:" in
#                       the certificates YAML)
#   CERTS_DIR           source directory (default: certs/ next to this script)
#   CERTS_CONFIG        certificates YAML (default: ../scripts/wazuh-certs-tool.yml of this checkout)
# ------------------------------------------------------------------------------

OLD_DIR=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
trap 'cd "$OLD_DIR"' EXIT
cd "$SCRIPT_DIR"

WAZUH_MANAGER_HOME="${WAZUH_MANAGER_HOME:-/var/wazuh-manager}"
# The manager configuration directory is fixed: a custom home never moves it.
CONF_DIR="/etc/wazuh-manager"
# ../scripts of this checkout, never $WAZUH_DEV_SCRIPTS (see init.sh: it can name
# another checkout or the pre-move location).
DEV_SCRIPTS="$(cd "${SCRIPT_DIR}/../scripts" && pwd)"
CERTS_DIR="${CERTS_DIR:-${SCRIPT_DIR}/certs}"
CERTS_CONFIG="${CERTS_CONFIG:-${DEV_SCRIPTS}/wazuh-certs-tool.yml}"
DEST_DIR="${CONF_DIR}/certs"
WAZUH_USER="wazuh-manager"
WAZUH_GROUP="wazuh-manager"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: this script must run as root (sudo ./wazuh_copy_certs.sh)." >&2
    exit 1
fi
command -v openssl >/dev/null 2>&1 || { echo "ERROR: required command not found: openssl" >&2; exit 1; }

# The credential resolver run below opens the keystore, which must not happen while the manager's
# daemons hold it; and a running manager could only be restarted after the new CA is published,
# which is what this script does. So it works on a stopped manager only.
CONTROL="${WAZUH_MANAGER_HOME}/bin/wazuh-manager-control"
# Captured, not piped into grep -q: under pipefail an early grep exit would fail the pipeline.
CONTROL_STATUS=""
if [ -x "${CONTROL}" ]; then
    CONTROL_STATUS="$("${CONTROL}" status 2>/dev/null || true)"
fi
case "${CONTROL_STATUS}" in
    *" is running"*)
        echo "ERROR: the manager is running; stop it first: ${CONTROL} stop" >&2
        exit 1
        ;;
esac

if ! id -u "${WAZUH_USER}" >/dev/null 2>&1; then
    echo "ERROR: user ${WAZUH_USER} does not exist (is the manager installed?)." >&2
    exit 1
fi
if ! getent group "${WAZUH_GROUP}" >/dev/null 2>&1; then
    echo "ERROR: group ${WAZUH_GROUP} does not exist (is the manager installed?)." >&2
    exit 1
fi

# First "- name:" under "manager:" in the certificates YAML (same awk as init.sh).
function manager_node_name() {
    awk '
      function indent(s) { match(s, /^[ \t]*/); return RLENGTH }
      /^[ \t]*#/ || /^[ \t]*$/ { next }
      /^[ \t]*manager:[ \t]*$/ { in_mgr = 1; mgr_indent = indent($0); next }
      in_mgr && /^[ \t]*[A-Za-z0-9_]+:[ \t]*$/ && indent($0) <= mgr_indent { in_mgr = 0 }
      in_mgr && /^[ \t]*-[ \t]*name:[ \t]*/ {
        sub(/^[ \t]*-[ \t]*name:[ \t]*/, ""); gsub(/["'"'"']/, ""); sub(/[ \t]+$/, "")
        print; exit
      }
    ' "$CERTS_CONFIG"
}

if [ -z "${MANAGER_NODE_NAME:-}" ]; then
    if [ ! -f "$CERTS_CONFIG" ]; then
        echo "ERROR: certificates configuration not found: $CERTS_CONFIG (set CERTS_CONFIG or MANAGER_NODE_NAME)." >&2
        exit 1
    fi
    MANAGER_NODE_NAME="$(manager_node_name)"
    if [ -z "$MANAGER_NODE_NAME" ]; then
        echo "ERROR: no manager node ('- name:' under 'manager:') in $CERTS_CONFIG." >&2
        exit 1
    fi
fi
echo "==> Manager node: ${MANAGER_NODE_NAME}"

# src|dst (always root:wazuh-manager 640). root-ca.key is not listed on purpose.
CERT_TABLE=(
    "root-ca.pem|root-ca.pem"
    "root-ca.pem|indexer-ca.pem"
    "${MANAGER_NODE_NAME}.pem|indexer-connector.pem"
    "${MANAGER_NODE_NAME}-key.pem|indexer-connector-key.pem"
    "${MANAGER_NODE_NAME}-remoted.pem|remoted.pem"
    "${MANAGER_NODE_NAME}-remoted-key.pem|remoted-key.pem"
    "${MANAGER_NODE_NAME}-remoted.pem|apid.pem"
    "${MANAGER_NODE_NAME}-remoted-key.pem|apid-key.pem"
)

for entry in "${CERT_TABLE[@]}"; do
    src="${entry%%|*}"
    if [ ! -s "${CERTS_DIR}/${src}" ]; then
        echo "ERROR: missing ${CERTS_DIR}/${src}; run ./init.sh --certs-only first." >&2
        exit 1
    fi
done

echo "==> Deploying certificates to ${DEST_DIR}..."
install -d -m 750 -o root -g "${WAZUH_GROUP}" "${DEST_DIR}"

for entry in "${CERT_TABLE[@]}"; do
    IFS='|' read -r src dst <<< "$entry"
    install -m 640 -o root -g "${WAZUH_GROUP}" "${CERTS_DIR}/${src}" "${DEST_DIR}/${dst}"
    echo "    ${src} -> ${dst} (root:${WAZUH_GROUP} 640)"
done

echo "==> Replacing the installation's CA with the e2e CA's certificate (no key)..."
install -d -m 700 -o root -g root "${CONF_DIR}/ca"
rm -f "${CONF_DIR}/ca/root-ca.key" "${CONF_DIR}/ca/.wazuh-manager-bootstrap-ca"
install -m 644 -o root -g root "${CERTS_DIR}/root-ca.pem" "${CONF_DIR}/ca/root-ca.pem"

# The installation also issued export/dashboard-client.pem from the CA just replaced; with no key
# in ca/ the resolver cannot reissue it and warns at every start that it no longer chains to the
# manager's CA. Issue it from the e2e CA instead, the way an operator with their own PKI provides
# it (CN=wazuh-dashboard, clientAuth only, a key of its own), and drop the resolver's marker so the
# pair counts as the operator's and is never replaced.
EXPORT_DIR="${CONF_DIR}/export"
if [ -d "${EXPORT_DIR}" ] && [ -s "${CERTS_DIR}/root-ca.key" ]; then
    echo "==> Issuing the dashboard client pair from the e2e CA into ${EXPORT_DIR}..."
    dc_tmp="$(mktemp -d)"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n' > "${dc_tmp}/ext.cnf"
    openssl req -new -newkey rsa:2048 -nodes -subj "/CN=wazuh-dashboard" \
        -keyout "${dc_tmp}/key.pem" -out "${dc_tmp}/req.csr" 2>/dev/null
    openssl x509 -req -in "${dc_tmp}/req.csr" -CA "${CERTS_DIR}/root-ca.pem" -CAkey "${CERTS_DIR}/root-ca.key" \
        -CAcreateserial -CAserial "${dc_tmp}/ca.srl" -days 3650 -sha256 -extfile "${dc_tmp}/ext.cnf" \
        -out "${dc_tmp}/cert.pem" 2>/dev/null
    rm -f "${EXPORT_DIR}/.dashboard-client.issued"
    install -m 600 -o root -g root "${dc_tmp}/key.pem" "${EXPORT_DIR}/dashboard-client-key.pem"
    install -m 644 -o root -g root "${dc_tmp}/cert.pem" "${EXPORT_DIR}/dashboard-client.pem"
    rm -rf "${dc_tmp}"
    openssl verify -CAfile "${CONF_DIR}/ca/root-ca.pem" -purpose sslclient "${EXPORT_DIR}/dashboard-client.pem" | sed 's/^/    /'
fi

echo "==> Verifying the deployed certificates..."
openssl verify -CAfile "${CONF_DIR}/ca/root-ca.pem" "${DEST_DIR}/remoted.pem" "${DEST_DIR}/apid.pem" | sed 's/^/    /'
openssl verify -CAfile "${DEST_DIR}/indexer-ca.pem" -purpose sslclient "${DEST_DIR}/indexer-connector.pem" | sed 's/^/    /'
if ! openssl x509 -in "${DEST_DIR}/remoted.pem" -noout -checkend 0 >/dev/null; then
    echo "ERROR: ${DEST_DIR}/remoted.pem has expired." >&2
    exit 1
fi
ls -l "${DEST_DIR}" | sed 's/^/    /'

RESOLVER="${WAZUH_MANAGER_HOME}/bin/wazuh-manager-resolve-credentials"
if [ -x "${RESOLVER}" ]; then
    echo "==> Publishing the new CA and checking what the next start will see..."
    "${RESOLVER}" --install -H "${WAZUH_MANAGER_HOME}" | sed 's/^/    /'
    "${RESOLVER}" --check -H "${WAZUH_MANAGER_HOME}" | sed 's/^/    /'
fi

CONF="${CONF_DIR}/wazuh-manager.conf"
if [ -f "$CONF" ]; then
    echo "==> <remote><https> certificate settings in ${CONF} (not edited):"
    sed -n '/<remote>/,/<\/remote>/{/<https>/,/<\/https>/p}' "$CONF" \
        | grep -E '<(certificate|key|ca_certificate)>' | sed 's/^[[:space:]]*/    /' || true
    echo "    (keys not listed use the defaults: ${DEST_DIR}/remoted.pem, ${DEST_DIR}/remoted-key.pem, ${DEST_DIR}/root-ca.pem)"
fi

echo "==> Done. Start the manager to load them: ${CONTROL} start"
