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
# Every daemon opens its pair after dropping privileges, through the group: the
# files stay root-owned so the service user can read them but never rewrite them.
# root-ca.key is never copied. wazuh-manager.conf is NOT edited: the <remote><https> defaults
# already point at these paths (the block is printed for review).
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

echo "==> Verifying the deployed certificates..."
openssl verify -CAfile "${DEST_DIR}/root-ca.pem" "${DEST_DIR}/remoted.pem" "${DEST_DIR}/apid.pem" "${DEST_DIR}/indexer-connector.pem" | sed 's/^/    /'
if ! openssl x509 -in "${DEST_DIR}/remoted.pem" -noout -checkend 0 >/dev/null; then
    echo "ERROR: ${DEST_DIR}/remoted.pem has expired." >&2
    exit 1
fi
ls -l "${DEST_DIR}" | sed 's/^/    /'

CONF="${CONF_DIR}/wazuh-manager.conf"
if [ -f "$CONF" ]; then
    echo "==> <remote><https> certificate settings in ${CONF} (not edited):"
    sed -n '/<remote>/,/<\/remote>/{/<https>/,/<\/https>/p}' "$CONF" \
        | grep -E '<(certificate|key|ca_certificate)>' | sed 's/^[[:space:]]*/    /' || true
    echo "    (keys not listed use the defaults: ${DEST_DIR}/remoted.pem, ${DEST_DIR}/remoted-key.pem, ${DEST_DIR}/root-ca.pem)"
fi

echo "==> Done. Restart the manager to load them: ${WAZUH_MANAGER_HOME}/bin/wazuh-manager-control restart"
