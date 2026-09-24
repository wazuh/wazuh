FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl procps hostname tini adduser lsb-release \
 && rm -rf /var/lib/apt/lists/*

# node/pkg holds either a wazuh-manager .deb (manifest/local/ci-run sources) or a
# wazuh-manager-tree.tar.gz snapshot of an existing install (source mode),
# produced by cluster/init.sh. In source mode wazuh-manager is created with the
# host's uid/gid (wazuh-manager.ids) before the tree is extracted with its
# numeric ownership, so the tree keeps the installer's owners and the setuid bit
# of bin/wazuh-manager-service-control without any chown.
COPY pkg/ /tmp/pkg/
RUN set -e; \
    if ls /tmp/pkg/*.deb >/dev/null 2>&1; then \
      apt-get update && apt-get install -y --no-install-recommends /tmp/pkg/*.deb && rm -rf /var/lib/apt/lists/*; \
    elif [ -f /tmp/pkg/wazuh-manager-tree.tar.gz ]; then \
      . /tmp/pkg/wazuh-manager.ids; \
      groupadd -r -g "$WAZUH_GID" wazuh-manager; \
      useradd -r -u "$WAZUH_UID" -g wazuh-manager -d /var/wazuh-manager -s /sbin/nologin wazuh-manager; \
      tar --numeric-owner -xzf /tmp/pkg/wazuh-manager-tree.tar.gz -C /var; \
    else \
      echo "no manager package or tree found in node/pkg; run cluster/init.sh first" >&2; exit 1; \
    fi; \
    rm -rf /tmp/pkg

COPY entrypoint.sh healthcheck.sh /
RUN chmod +x /entrypoint.sh /healthcheck.sh

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
