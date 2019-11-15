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

FROM base_agent AS wazuh-env-agent-base
FROM base_agent AS wazuh-env-agent-syscollector
FROM base_agent AS wazuh-env-agent-security
FROM base_agent AS wazuh-env-agent-manager
FROM base_agent AS wazuh-env-agent-cluster

FROM base_agent AS wazuh-env-agent-ciscat
RUN apt-get update && apt-get install openjdk-8-jdk -y
COPY configurations/ciscat/wazuh-agent-ciscat/test.keys /var/ossec/etc/test.keys
COPY configurations/ciscat/wazuh-agent-ciscat/ossec.conf /var/ossec/etc/ossec.conf
COPY configurations/ciscat/wazuh-agent-ciscat/healthcheck/healthcheck.py /tmp/healthcheck.py
COPY configurations/ciscat/wazuh-agent-ciscat/ciscat /var/ossec/wodles/ciscat
# RUN cd /var/ossec/wodles/ciscat && chmod +x CIS-CAT.sh

FROM base_agent AS wazuh-env-agent-security_white_rbac
FROM base_agent AS wazuh-env-agent-security_black_rbac
FROM base_agent AS wazuh-env-agent-agents_white_rbac
FROM base_agent AS wazuh-env-agent-agents_black_rbac
FROM wazuh-env-agent-ciscat AS wazuh-env-agent-ciscat_white_rbac
FROM wazuh-env-agent-ciscat AS wazuh-env-agent-ciscat_black_rbac
FROM base_agent AS wazuh-env-agent-rules_white_rbac
FROM base_agent AS wazuh-env-agent-rules_black_rbac
FROM base_agent AS wazuh-env-agent-decoders_white_rbac
FROM base_agent AS wazuh-env-agent-decoders_black_rbac
FROM base_agent AS wazuh-env-agent-syscollector_white_rbac
FROM base_agent AS wazuh-env-agent-syscollector_black_rbac
FROM base_agent AS wazuh-env-agent-overview_white_rbac
FROM base_agent AS wazuh-env-agent-overview_black_rbac
FROM base_agent AS wazuh-env-agent-lists_white_rbac
FROM base_agent AS wazuh-env-agent-lists_black_rbac
FROM base_agent AS wazuh-env-agent-syscheck_white_rbac
FROM base_agent AS wazuh-env-agent-syscheck_black_rbac

FROM wazuh-env-agent-${ENVIRONMENT}

ADD base/wazuh-agent/entrypoint.sh /scripts/entrypoint.sh
HEALTHCHECK --retries=30 --interval=10s --timeout=30s --start-period=30s CMD /usr/bin/python3 /tmp/healthcheck.py || exit 1
