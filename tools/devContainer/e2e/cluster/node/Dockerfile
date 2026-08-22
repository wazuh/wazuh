FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl procps hostname tini adduser lsb-release \
 && rm -rf /var/lib/apt/lists/*

# node/pkg holds either a wazuh-manager .deb (manifest/local/ci-run sources) or a
# wazuh-manager-tree.tar.gz snapshot of an existing install (source mode),
# produced by cluster/init.sh.
COPY pkg/ /tmp/pkg/
RUN set -e; \
    if ls /tmp/pkg/*.deb >/dev/null 2>&1; then \
      apt-get update && apt-get install -y --no-install-recommends /tmp/pkg/*.deb && rm -rf /var/lib/apt/lists/*; \
    elif [ -f /tmp/pkg/wazuh-manager-tree.tar.gz ]; then \
      tar -xzf /tmp/pkg/wazuh-manager-tree.tar.gz -C /; \
    else \
      echo "no manager package or tree found in node/pkg; run cluster/init.sh first" >&2; exit 1; \
    fi; \
    rm -rf /tmp/pkg

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
