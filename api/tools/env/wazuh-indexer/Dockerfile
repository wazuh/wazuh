FROM ubuntu:24.04

# ---------- Locale ----------
RUN apt-get update && apt-get install -y locales \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=en_US.utf8 \
    LC_ALL=en_US.utf8

# ---------- Base deps ----------
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    ca-certificates \
    gnupg \
    lsb-release \
    jq \
    unzip \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# ---------- GitHub CLI ----------
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] \
        https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update \
    && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

# ---------- User ----------
RUN groupadd -r wazuh-dashboard \
    && useradd -r -g wazuh-dashboard wazuh-dashboard

# ---------- Directories ----------
RUN mkdir -p \
      /usr/share/wazuh-dashboard \
      /var/log/wazuh-dashboard \
      /etc/wazuh-dashboard \
      /tmp/wazuh-dashboard

# ---------- Files ----------
COPY download_artifacts.sh /tmp/download_artifacts.sh
COPY entrypoint.sh /entrypoint.sh
COPY config.yml /tmp/opensearch_dashboards.yml

RUN chmod +x /tmp/download_artifacts.sh /entrypoint.sh

# ---------- Ports ----------
EXPOSE 4040

# ---------- Entrypoint ----------
ENTRYPOINT ["/entrypoint.sh"]
