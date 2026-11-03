# A REAL 4.x agent, installed from the public package repository, for the mixed-fleet
# scenario: 4.x on the legacy channel (1514/1515) and 5.x on HTTPS (1517), both through
# the same balancer, which is what a migration actually looks like.
FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ARG WAZUH_AGENT_VERSION=4.14.1-1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl gnupg2 apt-transport-https lsb-release ca-certificates \
        procps iproute2 openssl python3 && \
    rm -rf /var/lib/apt/lists/*

RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y wazuh-agent=${WAZUH_AGENT_VERSION} && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /scripts/entrypoint.sh
RUN chmod +x /scripts/entrypoint.sh
ENTRYPOINT ["/scripts/entrypoint.sh"]
