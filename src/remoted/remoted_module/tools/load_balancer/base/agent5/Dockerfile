# A REAL 5.x agent, from the package built off the branch under test.
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        procps iproute2 openssl ca-certificates curl python3 lsb-release adduser && \
    rm -rf /var/lib/apt/lists/*

# THE PACKAGE IS NOT IN THE REPOSITORY. Drop the .deb you want to test into this
# directory before building, under the name below. `setup_lab.sh --packages <dir>`
# does it for you. Always verify the package carries what you intend to measure: a
# build older than the feature under test produces silent false negatives.
COPY wazuh-agent.deb /tmp/wazuh-agent.deb
RUN dpkg -i /tmp/wazuh-agent.deb && rm -f /tmp/wazuh-agent.deb

COPY entrypoint.sh /scripts/entrypoint.sh
RUN chmod +x /scripts/entrypoint.sh
ENTRYPOINT ["/scripts/entrypoint.sh"]
