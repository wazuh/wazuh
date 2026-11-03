FROM rockylinux:8

RUN dnf -y update \
 && dnf -y install epel-release \
 && dnf -y install ca-certificates procps-ng hostname tini \
 && dnf clean all \
 && rm -rf /var/cache/dnf

# agents/init.sh saves the package for the target arch under a fixed name.
COPY pkgs/wazuh-agent_5x.rpm /tmp/wazuh-agent.rpm
RUN dnf -y install /tmp/wazuh-agent.rpm \
 && rm -f /tmp/wazuh-agent.rpm \
 && dnf clean all \
 && rm -rf /var/cache/dnf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/usr/bin/tini","--","/entrypoint.sh"]
