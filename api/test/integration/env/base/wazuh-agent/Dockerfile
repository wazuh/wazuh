ARG ENVIRONMENT

FROM ubuntu:18.04 as base_agent

RUN apt-get update && apt-get update && apt-get install curl apt-transport-https lsb-release gnupg2 -y && \
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
    echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list && \
    apt-get update

RUN apt-get install wazuh-agent -y

COPY configurations/base/wazuh-agent/config/test.keys /var/ossec/etc/test.keys
COPY configurations/base/wazuh-agent/config/ossec.conf /var/ossec/etc/ossec.conf
COPY configurations/base/wazuh-agent/healthcheck/healthcheck.py /tmp/healthcheck.py

FROM base_agent AS wazuh-env-agent-base
FROM base_agent AS wazuh-env-agent-syscollector

FROM base_agent AS wazuh-env-agent-ciscat
RUN apt-get update && apt-get install openjdk-8-jdk -y
COPY configurations/ciscat/wazuh-agent-ciscat/test.keys /var/ossec/etc/test.keys
COPY configurations/ciscat/wazuh-agent-ciscat/ossec.conf /var/ossec/etc/ossec.conf
COPY configurations/ciscat/wazuh-agent-ciscat/healthcheck/healthcheck.py /tmp/healthcheck.py
COPY configurations/ciscat/wazuh-agent-ciscat/ciscat /var/ossec/wodles/ciscat
RUN cd /var/ossec/wodles/ciscat && chmod +x CIS-CAT.sh
ADD configurations/ciscat/wazuh-agent-ciscat/entrypoint.sh /scripts/entrypoint.sh

FROM wazuh-env-agent-${ENVIRONMENT}

ADD base/wazuh-agent/entrypoint.sh /scripts/entrypoint.sh
HEALTHCHECK --retries=30 --interval=10s --timeout=30s --start-period=30s CMD /usr/bin/python /tmp/healthcheck.py || exit 1
