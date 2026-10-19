#!/bin/bash
set -e

# ----------------------------------------------------------------------------
# Stage the e2e TLS material, per package: the dashboard verifies each peer with
# that peer's own CA, certs/indexer-ca.pem (opensearch.ssl.certificateAuthorities)
# and certs/manager-ca.pem (wazuh_core.hosts.default.ca). On a single host the
# resolver imports them from /etc/wazuh-indexer/export and /etc/wazuh-manager/export;
# here the peers run elsewhere and every pair comes from the one e2e CA, so its
# certificate is staged under both names. A CA file without its .<peer>-ca.imported
# marker is the operator's: the resolver uses it as is and never replaces it.
#
# Every file the resolver reads as root must be root's and not writable by group
# or others; the service reads them through the group (root:wazuh-dashboard 0640
# in a root:wazuh-dashboard 0750 directory). Anything else is refused as UNSAFE.
# ----------------------------------------------------------------------------
CERTS_DIR=/etc/wazuh-dashboard/certs
echo "Staging the e2e certificates in ${CERTS_DIR}..."
install -d -m 750 -o root -g wazuh-dashboard "${CERTS_DIR}"
install -m 640 -o root -g wazuh-dashboard /certs/root-ca.pem       "${CERTS_DIR}/indexer-ca.pem"
install -m 640 -o root -g wazuh-dashboard /certs/root-ca.pem       "${CERTS_DIR}/manager-ca.pem"
install -m 640 -o root -g wazuh-dashboard /certs/dashboard.pem     "${CERTS_DIR}/dashboard.pem"
install -m 640 -o root -g wazuh-dashboard /certs/dashboard-key.pem "${CERTS_DIR}/dashboard-key.pem"
rm -f "${CERTS_DIR}/.indexer-ca.imported" "${CERTS_DIR}/.manager-ca.imported" "${CERTS_DIR}/root-ca.pem"

# ----------------------------------------------------------------------------
# Resolve the consumed passwords with the package's resolver.
#
# The container env (env_file .credentials.env) carries
# WAZUH_INDEXER_KIBANASERVER_PASSWORD and WAZUH_MANAGER_WUI_PASSWORD; the
# resolver reads the env before /etc/wazuh-dashboard/local.env and the peers'
# export/credentials.env (absent in this container), and stores them in the
# keystore (opensearch.username/opensearch.password and
# wazuh_core.hosts.default.password), never in opensearch_dashboards.yml.
# Tolerated failure: without the env it exits non-zero (it owns no password),
# and set -e would restart the container in a loop. Degraded, not demo: the
# dashboard starts and its indexer/manager connections stay unauthenticated
# until the env is fixed and the container recreated.
# ----------------------------------------------------------------------------
/usr/share/wazuh-dashboard/bin/resolve-credentials --prestart || echo "WARN: credentials resolution failed (degraded)"

# Start wazuh-dashboard service
echo "Starting wazuh-dashboard..."

sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards -c /etc/wazuh-dashboard/opensearch_dashboards.yml
