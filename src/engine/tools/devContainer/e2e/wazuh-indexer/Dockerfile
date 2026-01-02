FROM ubuntu:24.04

# Update and install dependencies
RUN apt-get update && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG=en_US.utf8

# Copy all files to a temporary location for installation
WORKDIR /tmp/wazuh-install
COPY . .

# Install wazuh-indexer
RUN apt install -y /tmp/wazuh-install/wazuh-indexer_5.0.0-latest_amd64.deb

# Configure knn memory circuit breaker limit
RUN echo "knn.memory.circuit_breaker.limit: 4096mb" >> /etc/wazuh-indexer/opensearch.yml

# Add Java security policy permissions for cgroup access
RUN cat <<'EOF' >> /etc/wazuh-indexer/jvm.options
-Djava.security.policy=all.policy
-Dpermission.java.io.FilePermission=/sys/fs/cgroup/-,read
EOF

# Create certs directory (will be populated by volume mount at runtime)
RUN mkdir -p /etc/wazuh-indexer/certs/

# Clean up installation files
RUN rm -rf /tmp/wazuh-install

# Set working directory
WORKDIR /root

# Wait for interactive debugging
#CMD [ "sleep", "infinity" ]
