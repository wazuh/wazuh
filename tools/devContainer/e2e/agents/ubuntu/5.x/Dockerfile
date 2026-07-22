FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Registration is configured at install time: the package post-install script
# writes the manager address and the enrollment password (authorization_pass_path)
# from these variables, so the agent enrolls automatically on start.
ARG WAZUH_MANAGER=host.docker.internal
ARG WAZUH_REGISTRATION_PASSWORD
RUN test -n "$WAZUH_REGISTRATION_PASSWORD" \
 || { echo "WAZUH_REGISTRATION_PASSWORD is required (the manager etc/authd.pass)" >&2; exit 1; }

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl procps hostname tini \
 && rm -rf /var/lib/apt/lists/*

# agents/init.sh saves the package for the target arch under a fixed name.
COPY pkgs/wazuh-agent_5x.deb /tmp/wazuh-agent.deb
RUN apt-get update \
 && WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_REGISTRATION_PASSWORD="$WAZUH_REGISTRATION_PASSWORD" \
      apt-get install -y --no-install-recommends /tmp/wazuh-agent.deb \
 && rm -f /tmp/wazuh-agent.deb \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/usr/bin/tini","--","/entrypoint.sh"]
