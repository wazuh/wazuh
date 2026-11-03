FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# curl is a hard dependency of the package; the rest is what the lab itself needs:
# python3 to drive the probe from inside the network, openssl to inspect certificates,
# iproute2/procps to see what is listening, ca-certificates for outbound TLS.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl python3 python3-cryptography openssl iproute2 procps \
        ca-certificates xz-utils less vim-tiny \
        lsb-release adduser && \
    rm -rf /var/lib/apt/lists/*

# The manager package: installed from the locally built .deb instead of compiled from
# source. install.sh takes tens of minutes and produces the same tree; the .deb is the
# artifact a production node actually receives, which is also what this lab is about.
# THE PACKAGE IS NOT IN THE REPOSITORY. Drop the .deb you want to test into this
# directory before building, under the name below. `setup_lab.sh --packages <dir>`
# does it for you. Always verify the package carries what you intend to measure: a
# build older than the feature under test produces silent false negatives.
COPY wazuh-manager.deb /tmp/wazuh-manager.deb
RUN dpkg -i /tmp/wazuh-manager.deb && rm -f /tmp/wazuh-manager.deb

COPY entrypoint.sh /scripts/entrypoint.sh
RUN chmod +x /scripts/entrypoint.sh

ENTRYPOINT ["/scripts/entrypoint.sh"]
