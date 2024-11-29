FROM wazuh-server-builder

ENV DEBIAN_FRONTEND="noninteractive"

RUN apt-get update && apt-get install -y vim apt-transport-https sqlite3

ADD entrypoint.sh /scripts/entrypoint.sh
ADD healthcheck.sh /scripts/healthcheck.sh
RUN chmod +x /scripts/healthcheck.sh

HEALTHCHECK --interval=5s --timeout=30s --start-period=5s --retries=35 CMD /scripts/healthcheck.sh
