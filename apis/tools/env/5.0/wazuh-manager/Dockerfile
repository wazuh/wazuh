FROM dev-wazuh-engine

ENV DEBIAN_FRONTEND="noninteractive"

RUN apt-get update && apt-get install -y python3 python3-pip vim curl apt-transport-https python3-cryptography sqlite3

ADD entrypoint.sh /scripts/entrypoint.sh
ADD healthcheck.sh /scripts/healthcheck.sh
RUN chmod +x /scripts/healthcheck.sh

HEALTHCHECK --interval=5s --timeout=30s --start-period=5s --retries=35 CMD /scripts/healthcheck.sh
