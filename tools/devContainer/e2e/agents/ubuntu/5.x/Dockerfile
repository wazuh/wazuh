FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl procps hostname tini \
 && rm -rf /var/lib/apt/lists/*

# agents/init.sh saves the package for the target arch under a fixed name.
COPY pkgs/wazuh-agent_5x.deb /tmp/wazuh-agent.deb
RUN apt-get update \
 && apt-get install -y --no-install-recommends /tmp/wazuh-agent.deb \
 && rm -f /tmp/wazuh-agent.deb \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/usr/bin/tini","--","/entrypoint.sh"]
