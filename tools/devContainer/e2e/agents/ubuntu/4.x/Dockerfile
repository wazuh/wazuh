FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl procps hostname tini \
 && rm -rf /var/lib/apt/lists/*

COPY pkgs/wazuh-agent_4*_amd64.deb /tmp/wazuh-agent.deb
RUN apt-get update \
 && apt-get install -y --no-install-recommends /tmp/wazuh-agent.deb \
 && rm -f /tmp/wazuh-agent.deb \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/usr/bin/tini","--","/entrypoint.sh"]
