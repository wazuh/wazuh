FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl openssl ca-certificates procps iproute2 lsb-release adduser && \
    rm -rf /var/lib/apt/lists/*

# THE PACKAGE IS NOT IN THE REPOSITORY. Drop the .deb you want to test into this
# directory before building, under the name below. `setup_lab.sh --packages <dir>`
# does it for you. Always verify the package carries what you intend to measure: a
# build older than the feature under test produces silent false negatives.
COPY wazuh-indexer.deb /tmp/wazuh-indexer.deb
RUN dpkg -i /tmp/wazuh-indexer.deb || apt-get -f install -y; rm -f /tmp/wazuh-indexer.deb

COPY entrypoint.sh /scripts/entrypoint.sh
RUN chmod +x /scripts/entrypoint.sh
ENTRYPOINT ["/scripts/entrypoint.sh"]
