FROM rockylinux:8

RUN dnf -y update \
 && dnf -y install epel-release \
 && dnf -y install curl ca-certificates procps-ng hostname tini \
 && rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH \
 && cat > /etc/yum.repos.d/wazuh.repo << 'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

RUN dnf -y install 'wazuh-agent-4.14.3*' \
 && dnf clean all \
 && rm -rf /var/cache/dnf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/usr/bin/tini","--","/entrypoint.sh"]