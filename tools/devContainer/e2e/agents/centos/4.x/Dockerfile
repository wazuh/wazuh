FROM rockylinux:8

RUN dnf -y update \
 && dnf -y install epel-release \
 && dnf -y install ca-certificates procps-ng hostname tini \
 && dnf clean all \
 && rm -rf /var/cache/dnf

COPY pkgs/wazuh-agent-4*.x86_64.rpm /tmp/wazuh-agent.rpm
RUN dnf -y install /tmp/wazuh-agent.rpm \
 && rm -f /tmp/wazuh-agent.rpm \
 && dnf clean all \
 && rm -rf /var/cache/dnf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/usr/bin/tini","--","/entrypoint.sh"]
