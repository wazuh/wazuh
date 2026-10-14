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
# Issue the manager's certificates here rather than letting the install do it: preloaded-vars.conf
# sets USER_RESOLVE_CREDENTIALS="n", so nothing credential-bearing is baked into the layer, and the
# SANs have to cover every manager service name in the compose environment anyway (see
# certs-config.yml) -- a pair minted against the build container's own hostname would not match.
# The api_ssl volume shared by the cluster containers is populated from this path. Issued with the
# devcontainer copy of the installation assistant tool (sources already in /wazuh).
#
# Certificates are the one credential it is safe to bake in: they are public material plus a key
# scoped to names only this test environment answers to. The credential resolver checks them at
# every start without reissuing them: the Server API pair against the CA in ca/, the indexer client
# pair (the manager node's certificate, issued with clientAuth) against certs/indexer-ca.pem. Only
# the CA's certificate goes to ca/, never its key, so no signing key reaches the layer and nothing
# can be issued in a container. ca/ is part of the image, so every node has it; certs/ is shared
# through the api_ssl volume.
#
# The Server API (apid) pair is the same listener pair: the API no longer generates its own
# certificate, so every image has to ship one, and the installation issues it with the remoted
# profile (serverAuth, leaf followed by the CA, the same SANs, localhost among them).
COPY base/manager/certs-config.yml /wazuh/certs-config.yml
RUN bash /wazuh/tools/devContainer/scripts/wazuh-certs-tool.sh -A -c /wazuh/certs-config.yml -o /tmp/wazuh-certificates && \
    install -d -o root -g wazuh-manager -m 750 /etc/wazuh-manager/certs && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/root-ca.pem /etc/wazuh-manager/certs/root-ca.pem && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/root-ca.pem /etc/wazuh-manager/certs/indexer-ca.pem && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager.pem /etc/wazuh-manager/certs/indexer-connector.pem && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager-key.pem /etc/wazuh-manager/certs/indexer-connector-key.pem && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager-remoted.pem /etc/wazuh-manager/certs/remoted.pem && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager-remoted-key.pem /etc/wazuh-manager/certs/remoted-key.pem && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager-remoted.pem /etc/wazuh-manager/certs/apid.pem && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager-remoted-key.pem /etc/wazuh-manager/certs/apid-key.pem && \
    chown root:wazuh-manager /etc/wazuh-manager/certs && chmod 0750 /etc/wazuh-manager/certs && \
    install -d -o root -g root -m 700 /etc/wazuh-manager/ca && \
    install -o root -g root -m 644 /tmp/wazuh-certificates/root-ca.pem /etc/wazuh-manager/ca/root-ca.pem && \
    rm -rf /tmp/wazuh-certificates
COPY base/manager/entrypoint.sh /scripts/entrypoint.sh

# HEALTHCHECK
HEALTHCHECK --retries=900 --interval=1s --timeout=30s --start-period=30s CMD /var/wazuh-manager/framework/python/bin/python3 /tmp_volume/healthcheck/healthcheck.py || exit 1
