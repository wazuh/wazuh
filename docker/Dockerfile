# Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
FROM amazonlinux:2023

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

ARG WAZUH_VERSION=5.0.0
ARG WAZUH_TAG_REVISION=1
ARG FILEBEAT_TEMPLATE_BRANCH=5.0.0
ARG FILEBEAT_CHANNEL=filebeat-oss
ARG FILEBEAT_VERSION=7.10.2
ARG WAZUH_FILEBEAT_MODULE
ARG S6_VERSION="v2.2.0.3"

RUN yum install curl-minimal xz gnupg tar gzip openssl findutils procps -y &&\
    yum clean all

COPY config/check_repository.sh /
COPY config/filebeat_module.sh /
COPY config/permanent_data.env config/permanent_data.sh /

RUN chmod 775 /check_repository.sh
RUN source /check_repository.sh

RUN yum install wazuh-manager-${WAZUH_VERSION}-${WAZUH_TAG_REVISION} -y && \
    yum clean all && \
    chmod 775 /filebeat_module.sh && \
    source /filebeat_module.sh && \
    rm /filebeat_module.sh && \
    curl --fail --silent -L https://github.com/just-containers/s6-overlay/releases/download/${S6_VERSION}/s6-overlay-amd64.tar.gz \
    -o /tmp/s6-overlay-amd64.tar.gz && \
    tar xzf /tmp/s6-overlay-amd64.tar.gz -C / --exclude="./bin" && \
    tar xzf /tmp/s6-overlay-amd64.tar.gz -C /usr ./bin && \
    rm  /tmp/s6-overlay-amd64.tar.gz

COPY config/etc/ /etc/
COPY --chown=root:wazuh config/create_user.py /var/ossec/framework/scripts/create_user.py

COPY config/filebeat.yml /etc/filebeat/

RUN chmod go-w /etc/filebeat/filebeat.yml

ADD https://raw.githubusercontent.com/wazuh/wazuh/$FILEBEAT_TEMPLATE_BRANCH/extensions/elasticsearch/7.x/wazuh-template.json /etc/filebeat
RUN chmod go-w /etc/filebeat/wazuh-template.json

# Prepare permanent data
# Sync calls are due to https://github.com/docker/docker/issues/9547

#Make mount directories for keep permissions

RUN mkdir -p /var/ossec/var/multigroups && \
    chown root:wazuh /var/ossec/var/multigroups && \
    chmod 770 /var/ossec/var/multigroups && \
    mkdir -p /var/ossec/agentless && \
    chown root:wazuh /var/ossec/agentless && \
    chmod 770 /var/ossec/agentless && \
    mkdir -p /var/ossec/active-response/bin && \
    chown root:wazuh /var/ossec/active-response/bin && \
    chmod 770 /var/ossec/active-response/bin && \
    chmod 755 /permanent_data.sh && \
    sync && /permanent_data.sh && \
    sync && rm /permanent_data.sh

RUN rm /etc/yum.repos.d/wazuh.repo

# Services ports
EXPOSE 55000/tcp 1514/tcp 1515/tcp 514/udp 1516/tcp

ENTRYPOINT [ "/init" ]
