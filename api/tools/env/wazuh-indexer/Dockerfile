FROM ubuntu:24.04

USER root

ARG GH_TOKEN
ENV GH_TOKEN=${GH_TOKEN}

# Update and install dependencies
RUN apt-get update && apt-get install -y locales bash curl && rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG=en_US.utf8

SHELL ["/bin/bash", "-c"]

RUN set -euo pipefail \
    && [[ -n "$HOME" ]]
# Scripts
COPY download_indexer.sh /usr/share/wazuh/download_indexer.sh
COPY entrypoint.sh /usr/share/wazuh/entrypoint.sh

RUN chmod +x /usr/share/wazuh/*.sh

# Download wazuh-indexer package
RUN /usr/share/wazuh/download_indexer.sh

# Install wazuh-indexer
RUN dpkg -i /usr/share/wazuh/wazuh-indexer_*.deb || (apt-get update && apt-get -f install -y)

# Set working directory
WORKDIR /root

ENTRYPOINT ["/usr/share/wazuh/entrypoint.sh"]
