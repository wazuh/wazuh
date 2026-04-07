FROM rockylinux:8

RUN dnf -y update \
 && dnf -y install epel-release \
 && dnf -y install ca-certificates procps-ng hostname tini \
 && rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

COPY wazuh-agent_5.0.0-0_x86_64_*.rpm /tmp/

RUN set -eux; \
    rpm=$(echo /tmp/wazuh-agent_5.0.0-0_x86_64_*.rpm); \
    dnf -y install "$rpm"; \
    rm -f "$rpm"; \
    dnf clean all; \
    rm -rf /var/cache/dnf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/usr/bin/tini","--","/entrypoint.sh"]
