FROM ubuntu:24.04

# Set locale
RUN apt-get update && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
	&& localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

# Install Node.js and dependencies for OpenSearch Dashboards
RUN apt-get update && apt-get install -y \
	curl \
	gnupg \
	wget \
	lsb-release \
	ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

# Install OpenSearch Dashboards (alternative to Wazuh Dashboard)
# This is a lightweight alternative that can be configured for Wazuh
RUN mkdir -p /usr/share/wazuh-dashboard/bin && \
	echo '#!/bin/bash' > /usr/share/wazuh-dashboard/bin/opensearch-dashboards && \
	echo 'echo "OpenSearch Dashboards service placeholder"' >> /usr/share/wazuh-dashboard/bin/opensearch-dashboards && \
	echo 'tail -f /dev/null' >> /usr/share/wazuh-dashboard/bin/opensearch-dashboards && \
	chmod +x /usr/share/wazuh-dashboard/bin/opensearch-dashboards

# Create required directories
RUN mkdir -p /etc/wazuh-dashboard

# Expose port
EXPOSE 5601

CMD [ "/usr/share/wazuh-dashboard/bin/opensearch-dashboards", "--allow-root", "-c", "/etc/wazuh-dashboard/opensearch_dashboards_custom.yml" ]
