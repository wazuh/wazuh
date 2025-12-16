FROM ubuntu:24.04

# Set locale
RUN apt-get update && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

# Install dependencies for downloading and installing the dashboard
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    wget \
    lsb-release \
    ca-certificates \
    sudo \
    jq \
    unzip \
	gosu \
    && rm -rf /var/lib/apt/lists/*

# Install GitHub CLI (needed for download script)
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

# Create wazuh-dashboard user
RUN groupadd -r wazuh-dashboard && useradd -r -g wazuh-dashboard wazuh-dashboard

# Copy scripts
COPY download_artifacts.sh /tmp/download_artifacts.sh
COPY entrypoint.sh /tmp/entrypoint.sh
COPY config.yml /tmp/opensearch_dashboards.yml
RUN chmod +x /tmp/download_artifacts.sh /tmp/entrypoint.sh

# Create directory for dashboard installation
RUN mkdir -p /usr/share/wazuh-dashboard /var/log/wazuh-dashboard /etc/wazuh-dashboard \
    && chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard /var/log/wazuh-dashboard /etc/wazuh-dashboard

# Create a directory for downloaded artifacts
RUN mkdir -p /tmp/wazuh-dashboard

# Expose dashboard port
EXPOSE 4040

# Use our custom entrypoint
ENTRYPOINT ["/tmp/entrypoint.sh"]
