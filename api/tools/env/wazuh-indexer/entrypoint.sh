#!/usr/bin/env bash
set -Eeuo pipefail

echo "=== Wazuh Dashboard Entrypoint ==="

# ---------- Defaults ----------
OPENSEARCH_HOSTS="${OPENSEARCH_HOSTS:-https://wazuh-indexer:9200}"
OPENSEARCH_USERNAME="${OPENSEARCH_USERNAME:-admin}"
OPENSEARCH_PASSWORD="${OPENSEARCH_PASSWORD:-admin}"
DASHBOARD_HOST="${DASHBOARD_HOST:-0.0.0.0}"
DASHBOARD_PORT="${DASHBOARD_PORT:-4040}"
SKIP_INDEXER_DOWNLOAD="${SKIP_INDEXER_DOWNLOAD:-false}"

export OPENSEARCH_HOSTS OPENSEARCH_USERNAME OPENSEARCH_PASSWORD \
       DASHBOARD_HOST DASHBOARD_PORT

# ---------- Directories ----------
mkdir -p \
  /usr/share/wazuh-dashboard/{config,data,logs} \
  /var/log/wazuh-dashboard

# ---------- Download & install ----------
if [[ "${SKIP_INDEXER_DOWNLOAD}" != "true" ]]; then
  if [[ -z "${GH_TOKEN:-}" ]]; then
    echo "ERROR: GH_TOKEN not set and SKIP_INDEXER_DOWNLOAD=false"
    exit 1
  fi

  echo "Using GH_TOKEN: ${GH_TOKEN:0:5}********"

  bash /tmp/download_artifacts.sh

  DEB="/tmp/wazuh-dashboard/wazuh-dashboard_5.0.0-latest_amd64.deb"
  if [[ ! -f "${DEB}" ]]; then
    echo "ERROR: Dashboard package not found: ${DEB}"
    exit 1
  fi

  echo "Installing Wazuh Dashboard package..."
  dpkg -i "${DEB}" || {
    echo "Fixing dependencies..."
    apt-get update && apt-get install -f -y
  }

  if [[ -d /etc/wazuh-dashboard ]]; then
    cp -r /etc/wazuh-dashboard/* /usr/share/wazuh-dashboard/config/ 2>/dev/null || true
  fi
else
  echo "INFO: SKIP_INDEXER_DOWNLOAD=true, skipping artifact download"
fi

# ---------- Config ----------
cp /tmp/opensearch_dashboards.yml \
   /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml

# ---------- SSL ----------
if [[ -f /etc/wazuh-dashboard/certs/dashboard.pem ]] && \
   [[ -f /etc/wazuh-dashboard/certs/dashboard-key.pem ]]; then
  cat >> /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml <<EOF
server.ssl.enabled: true
server.ssl.certificate: /etc/wazuh-dashboard/certs/dashboard.pem
server.ssl.key: /etc/wazuh-dashboard/certs/dashboard-key.pem
EOF
fi

# ---------- Permissions ----------
chown -R wazuh-dashboard:wazuh-dashboard \
  /usr/share/wazuh-dashboard \
  /var/log/wazuh-dashboard

# ---------- Wait for OpenSearch ----------
echo "Waiting for OpenSearch..."
until curl -k -u "${OPENSEARCH_USERNAME}:${OPENSEARCH_PASSWORD}" \
  "${OPENSEARCH_HOSTS}" >/dev/null 2>&1; do
  sleep 5
done

echo "OpenSearch is ready."

# ---------- Start Dashboard (drop privileges) ----------
echo "Starting Wazuh Dashboard as wazuh-dashboard..."

if [[ -x /usr/share/wazuh-dashboard/bin/opensearch-dashboards ]]; then
  exec gosu wazuh-dashboard \
    /usr/share/wazuh-dashboard/bin/opensearch-dashboards
elif command -v opensearch-dashboards >/dev/null 2>&1; then
  exec gosu wazuh-dashboard opensearch-dashboards
else
  echo "ERROR: opensearch-dashboards binary not found"
  find /usr -name "*dashboards*" -type f -executable | head -20
  exit 1
fi
