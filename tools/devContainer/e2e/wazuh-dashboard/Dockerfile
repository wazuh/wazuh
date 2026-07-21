FROM ubuntu:24.04

# Update and install dependencies
RUN apt-get update && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG=en_US.utf8

# Copy all files to a temporary location for installation
WORKDIR /tmp/wazuh-install
COPY . .

# Install wazuh-dashboard
RUN apt update && apt install -y adduser curl libcap2-bin bash sudo
RUN apt install -y /tmp/wazuh-install/wazuh-dashboard_5.0.0-latest_amd64.deb

# Replace default indexer host `opensearch.hosts: https://localhost:9200` with `opensearch.hosts: https://wazuh-indexer:9200`
RUN sed -i 's|^opensearch.hosts: .*|opensearch.hosts: ["https://wazuh-indexer:9200"]|' /etc/wazuh-dashboard/opensearch_dashboards.yml

# Replace `url: https://localhost` with `url: https://host.docker.internal`
RUN sed -i 's| url: .*| url: "https://host.docker.internal"|' /etc/wazuh-dashboard/opensearch_dashboards.yml

# Clean up installation files
RUN rm -rf /tmp/wazuh-install

# Set working directory
WORKDIR /root

# Wait for interactive debugging
#CMD [ "sleep", "infinity" ]
