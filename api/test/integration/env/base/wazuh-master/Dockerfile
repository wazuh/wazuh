ARG ENVIRONMENT

FROM ubuntu:18.04 AS base

ARG wazuhbranch

# install supervisor just in case it isn't already installed
RUN apt-get update && apt-get install -y openssh-server supervisor

ADD base/wazuh-master/supervisord.conf /etc/supervisor/conf.d/
ADD base/wazuh-master/sshd.conf /etc/supervisor/conf.d/
RUN mkdir -p /var/run/sshd /var/log/supervisor

ADD base/wazuh-master/id_rsa.pub ./

# http://www.linuxproblem.org/art_9.html
RUN mkdir /root/.ssh
RUN cat ./id_rsa.pub >> /root/.ssh/authorized_keys

RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

EXPOSE 22


##RUN apt-get update && apt-get install python git gnupg2 gcc make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python-cryptography -y && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list && apt-get update && apt-get install wazuh-manager=3.8.2-1

RUN apt-get update && apt-get install python git gnupg2 gcc make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python-cryptography -y && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/staging/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh.list
# && apt-get update && apt-get install wazuh-manager


RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout $wazuhbranch
#RUN git clone https://github.com/wazuh/wazuh-ruleset && cd /wazuh-ruleset && git checkout dev-flask-poc
# RUN cd /wazuh && git pull

# ÑAPA!!! -> para evitar errores al instalar paquetes Python
RUN sed -i 's!--index-url=file://${ROUTE_PATH}/${EXTERNAL_CPYTHON}/Dependencies/simple!!' /wazuh/src/Makefile
COPY base/wazuh-master/preloaded-vars.conf /wazuh/etc/preloaded-vars.conf

RUN /wazuh/install.sh

# install pip libraries for development
RUN /var/ossec/framework/python/bin/pip3 install pytest==4.5.0 tavern pytest-cov defusedxml ptvsd pydevd-pycharm~=191.7479.30 freezegun

RUN curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add - &&\
    echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-6.x.list &&\
    apt-get update &&\
    apt-get install filebeat=6.6.0 &&\
    curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/3.9/extensions/filebeat/filebeat.yml &&\
    sed -i 's/YOUR_ELASTIC_SERVER_IP/logstash/' /etc/filebeat/filebeat.yml

#####

ONBUILD COPY configurations/base/wazuh-master/test_config/ossec.conf /var/ossec/etc/ossec.conf
ONBUILD COPY configurations/base/wazuh-master/test_config/test.keys /var/ossec/etc/client.keys
ONBUILD COPY configurations/base/wazuh-master/test_config/agent-groups /var/ossec/queue/agent-groups
ONBUILD COPY configurations/base/wazuh-master/test_config/multigroups /var/ossec/var/multigroups
ONBUILD COPY configurations/base/wazuh-master/test_config/shared /var/ossec/etc/shared
ONBUILD COPY configurations/base/wazuh-master/test_config/agent-info /var/ossec/queue/agent-info
ONBUILD COPY configurations/base/wazuh-master/healthcheck/healthcheck.py /tmp/healthcheck.py
ONBUILD COPY configurations/base/wazuh-master/healthcheck/agent_control_check.txt /tmp/agent_control_check.txt

FROM base AS wazuh-env-base

FROM base AS wazuh-env-ciscat

FROM base AS wazuh-env-syscollector
ONBUILD COPY configurations/syscollector/wazuh-master/ossec.conf /var/ossec/etc/ossec.conf
ONBUILD COPY configurations/syscollector/wazuh-master/healthcheck/healthcheck.py /tmp/healthcheck.py
ONBUILD COPY configurations/syscollector/wazuh-master/healthcheck/syscollector_check.txt /tmp/syscollector_check.txt

FROM wazuh-env-${ENVIRONMENT}

ADD base/wazuh-master/entrypoint.sh /scripts/entrypoint.sh
HEALTHCHECK --retries=30 --interval=10s --timeout=30s --start-period=30s CMD /usr/bin/python /tmp/healthcheck.py || exit 0

# CISCAT is on agent dockerfile
