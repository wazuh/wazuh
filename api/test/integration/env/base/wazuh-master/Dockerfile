ARG ENVIRONMENT

FROM ubuntu:18.04 AS base

ARG wazuhbranch

# install supervisor just in case it isn't already installed
RUN apt-get update && apt-get install -y openssh-server supervisor
ADD base/wazuh-master/supervisord.conf /etc/supervisor/conf.d/

RUN apt-get update && apt-get install python git gnupg2 gcc make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python-cryptography -y && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/staging/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh.list

RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout $wazuhbranch

# ÑAPA!!! -> para evitar errores al instalar paquetes Python
RUN sed -i 's!--index-url=file://${ROUTE_PATH}/${EXTERNAL_CPYTHON}/Dependencies/simple!!' /wazuh/src/Makefile
COPY base/wazuh-master/preloaded-vars.conf /wazuh/etc/preloaded-vars.conf

RUN /wazuh/install.sh

#####

ONBUILD COPY configurations/base/wazuh-master/config/ossec.conf /var/ossec/etc/ossec.conf
ONBUILD COPY configurations/base/wazuh-master/config/test.keys /var/ossec/etc/client.keys
ONBUILD COPY configurations/base/wazuh-master/config/agent-groups /var/ossec/queue/agent-groups
ONBUILD COPY configurations/base/wazuh-master/config/multigroups /var/ossec/var/multigroups
ONBUILD COPY configurations/base/wazuh-master/config/shared /var/ossec/etc/shared
ONBUILD COPY configurations/base/wazuh-master/config/agent-info /var/ossec/queue/agent-info
ONBUILD COPY configurations/base/wazuh-master/healthcheck/healthcheck.py /tmp/healthcheck.py
ONBUILD COPY configurations/base/wazuh-master/healthcheck/agent_control_check.txt /tmp/agent_control_check.txt

FROM base AS wazuh-env-base
FROM base AS wazuh-env-ciscat

FROM base AS wazuh-env-syscollector
ONBUILD COPY configurations/syscollector/wazuh-master/ossec.conf /var/ossec/etc/ossec.conf

FROM base AS wazuh-env-security
ONBUILD COPY configurations/security/wazuh-master/rbac.db /var/ossec/api/configuration/security/rbac.db

FROM wazuh-env-${ENVIRONMENT}

ADD base/wazuh-master/entrypoint.sh /scripts/entrypoint.sh
HEALTHCHECK --retries=30 --interval=10s --timeout=30s --start-period=30s CMD /usr/bin/python3 /tmp/healthcheck.py || exit 1

