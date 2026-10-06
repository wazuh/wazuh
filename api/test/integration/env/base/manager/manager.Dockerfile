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
# scoped to names only this test environment answers to, and the resolver never re-examines a pair
# once it is in place -- not at service start, not on upgrade. No CA directory is left behind, so
# no signing key reaches the layer.
#
# The same RUN also issues the Server API (apid) pair, signed by that CA: the API no longer
# generates its own certificate, so every image has to ship one. It is issued before the CA
# directory is removed, in the same layer, so the CA key still never persists.
COPY base/manager/certs-config.yml /wazuh/certs-config.yml
RUN bash /wazuh/tools/devContainer/scripts/wazuh-certs-tool.sh -A -c /wazuh/certs-config.yml -o /tmp/wazuh-certificates && \
    mkdir -p /var/wazuh-manager/etc/certs && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/root-ca.pem /var/wazuh-manager/etc/certs/root-ca.pem && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager.pem /var/wazuh-manager/etc/certs/indexer-connector.pem && \
    install -o root -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager-key.pem /var/wazuh-manager/etc/certs/indexer-connector-key.pem && \
    install -o wazuh-manager -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager-remoted.pem /var/wazuh-manager/etc/certs/remoted.pem && \
    install -o wazuh-manager -g wazuh-manager -m 640 /tmp/wazuh-certificates/wazuh-manager-remoted-key.pem /var/wazuh-manager/etc/certs/remoted-key.pem && \
    CA_DIR=/tmp/wazuh-certificates && OUT=/tmp/wazuh-certificates && \
    printf '%s\n' \
      'basicConstraints = critical,CA:FALSE' \
      'keyUsage = critical,digitalSignature,keyEncipherment' \
      'extendedKeyUsage = serverAuth' \
      'subjectAltName = DNS:localhost' \
      'subjectKeyIdentifier = hash' \
      'authorityKeyIdentifier = keyid,issuer' > "$OUT/apid.ext" && \
    (umask 077; openssl req -new -nodes -newkey rsa:2048 -sha256 \
      -subj '/C=US/ST=California/L=San Francisco/O=Wazuh/CN=wazuh.com' \
      -keyout "$OUT/apid-key.pem" -out "$OUT/apid.csr") && \
    openssl x509 -req -sha256 -days 3650 -set_serial "0x$(openssl rand -hex 16)" \
      -in "$OUT/apid.csr" -CA "$CA_DIR/root-ca.pem" -CAkey "$CA_DIR/root-ca.key" \
      -extfile "$OUT/apid.ext" -out "$OUT/apid.pem" && \
    rm -f "$OUT/apid.csr" "$OUT/apid.ext" && \
    openssl verify -purpose sslserver -verify_hostname localhost -CAfile "$CA_DIR/root-ca.pem" "$OUT/apid.pem" && \
    install -o wazuh-manager -g wazuh-manager -m 640 /tmp/wazuh-certificates/apid.pem /var/wazuh-manager/etc/certs/apid.pem && \
    install -o wazuh-manager -g wazuh-manager -m 640 /tmp/wazuh-certificates/apid-key.pem /var/wazuh-manager/etc/certs/apid-key.pem && \
    rm -rf /tmp/wazuh-certificates /etc/wazuh/ca
COPY base/manager/entrypoint.sh /scripts/entrypoint.sh

# HEALTHCHECK
HEALTHCHECK --retries=900 --interval=1s --timeout=30s --start-period=30s CMD /var/wazuh-manager/framework/python/bin/python3 /tmp_volume/healthcheck/healthcheck.py || exit 1
