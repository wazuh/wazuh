#!/bin/bash
set -e

echo "=== Wazuh Dashboard Entrypoint ==="

# Set default environment variables
export OPENSEARCH_HOSTS="${OPENSEARCH_HOSTS:-https://wazuh-indexer:9200}"
export OPENSEARCH_USERNAME="${OPENSEARCH_USERNAME:-admin}"
export OPENSEARCH_PASSWORD="${OPENSEARCH_PASSWORD:-admin}"
export DASHBOARD_PORT="${DASHBOARD_PORT:-5601}"
export DASHBOARD_HOST="${DASHBOARD_HOST:-0.0.0.0}"

# Create directories if they don't exist
mkdir -p /usr/share/wazuh-dashboard/config /usr/share/wazuh-dashboard/data /usr/share/wazuh-dashboard/logs

# Check if we should download artifacts
if [[ "${SKIP_INDEXER_DOWNLOAD:-}" == "true" ]]; then
  echo "INFO: SKIP_INDEXER_DOWNLOAD is true -> skipping dashboard artifact download"
else
  if [ -z "$GH_TOKEN" ]; then
    echo "ERROR: GH_TOKEN not set and SKIP_INDEXER_DOWNLOAD not enabled"
    echo "Set GH_TOKEN=<token> or SKIP_INDEXER_DOWNLOAD=true to skip this step"
    exit 1
  fi

  echo "Using GH_TOKEN (masked): ${GH_TOKEN:0:5}********"

  # Run download script
  bash /tmp/download_artifacts.sh || {
    echo "ERROR: download_artifacts.sh failed."
    echo "If this is a dev environment and you don't need remote artifacts, try setting SKIP_INDEXER_DOWNLOAD=true"
    exit 1
  }
  
  # Install the downloaded .deb package
  if [ -f "/tmp/wazuh-dashboard/wazuh-dashboard_5.0.0-latest_amd64.deb" ]; then
    echo "Installing Wazuh Dashboard package..."
    # Switch to root temporarily to install the package
    dpkg -i /tmp/wazuh-dashboard/wazuh-dashboard_5.0.0-latest_amd64.deb || {
      echo "WARNING: dpkg installation had issues, attempting to fix dependencies..."
      apt-get update && apt-get install -f -y
    }
    
    # Copy default configuration if it exists
    if [ -d "/etc/wazuh-dashboard" ]; then
      echo "Copying dashboard configuration..."
      cp -r /etc/wazuh-dashboard/* /usr/share/wazuh-dashboard/config/ 2>/dev/null || true
    fi
    
    # Set proper permissions
    chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard /var/log/wazuh-dashboard
  else
    echo "ERROR: Dashboard package not found at /tmp/wazuh-dashboard/wazuh-dashboard_5.0.0-latest_amd64.deb"
    exit 1
  fi
fi

# Create or update configuration file
cp /tmp/opensearch_dashboards.yml /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
# cat > /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml << EOF
# server.host: "${DASHBOARD_HOST}"
# server.port: ${DASHBOARD_PORT}
# server.ssl.enabled: false
# opensearch.hosts: ${OPENSEARCH_HOSTS}
# opensearch.username: ${OPENSEARCH_USERNAME}
# opensearch.password: ${OPENSEARCH_PASSWORD}
# opensearch.ssl.verificationMode: none
# opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
# opensearch_security.multitenancy.enabled: true
# opensearch_security.multitenancy.tenants.preferred: ["Global", "Private"]
# opensearch_security.readonly_mode.roles: ["kibana_read_only"]
# # Custom branding
# wazuh_customization.enabled: true
# EOF

# If SSL certificates are provided, enable SSL
if [ -f "/etc/wazuh-dashboard/certs/dashboard.pem" ] && [ -f "/etc/wazuh-dashboard/certs/dashboard-key.pem" ]; then
  cat >> /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml << EOF
server.ssl.enabled: true
server.ssl.certificate: /etc/wazuh-dashboard/certs/dashboard.pem
server.ssl.key: /etc/wazuh-dashboard/certs/dashboard-key.pem
EOF
fi

# Wait for OpenSearch/Indexer to be ready
echo "Waiting for OpenSearch to be ready..."
until curl -k -u "${OPENSEARCH_USERNAME}:${OPENSEARCH_PASSWORD}" "${OPENSEARCH_HOSTS}" >/dev/null 2>&1; do
  echo "OpenSearch not ready yet, waiting..."
  sleep 5
done

echo "OpenSearch is ready. Starting Wazuh Dashboard..."

# Start the dashboard
# Note: The actual command to start might vary based on the installation
# Try to find and execute the dashboard binary
if [ -f "/usr/share/wazuh-dashboard/bin/opensearch-dashboards" ]; then
  exec /usr/share/wazuh-dashboard/bin/opensearch-dashboards
elif [ -f "/usr/share/opensearch-dashboards/bin/opensearch-dashboards" ]; then
  exec /usr/share/opensearch-dashboards/bin/opensearch-dashboards
elif which opensearch-dashboards > /dev/null 2>&1; then
  exec opensearch-dashboards
else
  echo "ERROR: Could not find opensearch-dashboards binary"
  echo "Trying to locate it..."
  find /usr -name "*dashboards*" -type f -executable 2>/dev/null | head -20
  exit 1
fi
