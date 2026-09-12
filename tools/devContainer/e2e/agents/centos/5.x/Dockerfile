FROM rockylinux:8

# Registration is configured at install time: the package post-install script
# writes the manager address and the enrollment password (authorization_pass_path)
# from these variables, so the agent enrolls automatically on start.
ARG WAZUH_MANAGER=host.docker.internal
ARG WAZUH_REGISTRATION_PASSWORD
RUN test -n "$WAZUH_REGISTRATION_PASSWORD" \
 || { echo "WAZUH_REGISTRATION_PASSWORD is required (the manager etc/authd.pass)" >&2; exit 1; }

RUN dnf -y update \
 && dnf -y install epel-release \
 && dnf -y install ca-certificates procps-ng hostname tini \
 && dnf clean all \
 && rm -rf /var/cache/dnf

# agents/init.sh saves the package for the target arch under a fixed name.
COPY pkgs/wazuh-agent_5x.rpm /tmp/wazuh-agent.rpm
RUN WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_REGISTRATION_PASSWORD="$WAZUH_REGISTRATION_PASSWORD" \
      dnf -y install /tmp/wazuh-agent.rpm \
 && rm -f /tmp/wazuh-agent.rpm \
 && dnf clean all \
 && rm -rf /var/cache/dnf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/usr/bin/tini","--","/entrypoint.sh"]
