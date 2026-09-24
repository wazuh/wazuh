FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN rm -f /var/lib/dpkg/statoverride && \
    rm -f /var/lib/dpkg/lock && \
    dpkg --configure -a && \
    apt-get -f install

RUN apt-get update && apt-get install supervisor wget git python3 gnupg2 gcc g++ curl make vim libc6-dev \
    policycoreutils automake autoconf libtool apt-transport-https lsb-release python3-cryptography sqlite3 cmake openssl -y \
    --option=Dpkg::Options::=--force-confdef

RUN wget http://archive.ubuntu.com/ubuntu/pool/main/r/rtmpdump/librtmp1_2.4+20151223.gitfa8646d.1-2build4_amd64.deb && \
    dpkg -i librtmp1_2.4+20151223.gitfa8646d.1-2build4_amd64.deb && \
    rm librtmp1_2.4+20151223.gitfa8646d.1-2build4_amd64.deb && \
    rm -rf /var/lib/apt/lists/* && ldconfig

# INSTALL MANAGER
# Cache invalidated: WazuhLogs tag schema updated to allow parentheses in log tags (alphanumeric_symbols).
ARG WAZUH_BRANCH

ADD base/manager/supervisord.conf /etc/supervisor/conf.d/

RUN mkdir wazuh && curl -sL https://github.com/wazuh/wazuh/tarball/${WAZUH_BRANCH} | tar zx --strip-components=1 -C wazuh
COPY base/manager/preloaded-vars.conf /wazuh/etc/preloaded-vars.conf
RUN /wazuh/install.sh
# Replace the certificates install.sh issued with a set whose SANs cover every manager service name
# in the compose environment: the api_ssl volume shared by the cluster containers is populated from
# this image (see certs-config.yml), and a pair minted against the build container's own hostname
# would not match. Issued with the devcontainer copy of the installation assistant tool (sources
# already in /wazuh).
COPY base/manager/certs-config.yml /wazuh/certs-config.yml
# Overwriting them is enough. The credential resolver issues certificates at installation and never
# looks at them again -- not at service start, not on upgrade -- so nothing here has to reproduce
# the provenance of the pair it replaces, and the shared CA directory is not consulted. The
# bootstrap CA install.sh left behind goes with it: its private key has no business being baked
# into an image layer every container shares.
RUN bash /wazuh/tools/devContainer/scripts/wazuh-certs-tool.sh -A -c /wazuh/certs-config.yml -o /tmp/wazuh-certificates && \
    mkdir -p /var/wazuh-manager/etc/certs && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/root-ca.pem /var/wazuh-manager/etc/certs/root-ca.pem && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager.pem /var/wazuh-manager/etc/certs/indexer-connector.pem && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager-key.pem /var/wazuh-manager/etc/certs/indexer-connector-key.pem && \
    install -o wazuh-manager -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager-remoted.pem /var/wazuh-manager/etc/certs/remoted.pem && \
    install -o wazuh-manager -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager-remoted-key.pem /var/wazuh-manager/etc/certs/remoted-key.pem && \
    rm -rf /tmp/wazuh-certificates /etc/wazuh/ca
COPY base/manager/entrypoint.sh /scripts/entrypoint.sh

# HEALTHCHECK
HEALTHCHECK --retries=900 --interval=1s --timeout=30s --start-period=30s CMD /var/wazuh-manager/framework/python/bin/python3 /tmp_volume/healthcheck/healthcheck.py || exit 1
