FROM ubuntu:18.04

RUN apt-get update && apt-get install -y curl apt-transport-https lsb-release gnupg2
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
    echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && apt-get install wazuh-agent=3.13.2-1 -y

COPY base/agent/entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --retries=900 --interval=1s --timeout=40s --start-period=30s CMD /usr/bin/python3 /tmp_volume/healthcheck/legacy_healthcheck.py || exit 1
