ARG ENVIRONMENT

FROM ubuntu:16.04 as base_agent

RUN apt-get update && apt-get update && apt-get install curl apt-transport-https lsb-release gnupg2 -y && \
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
    echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list && \
    apt-get update

RUN apt-get install wazuh-agent -y

COPY configurations/base/wazuh-agent/config/test.keys /var/ossec/etc/test.keys
COPY configurations/base/wazuh-agent/config/ossec.conf /var/ossec/etc/ossec.conf
COPY configurations/base/wazuh-agent/healthcheck/healthcheck.py /tmp/healthcheck.py
COPY configurations/tmp/agents/ /configuration_files/

ADD base/wazuh-agent/entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --retries=30 --interval=10s --timeout=30s --start-period=30s CMD /usr/bin/python3 /tmp/healthcheck.py || exit 1
