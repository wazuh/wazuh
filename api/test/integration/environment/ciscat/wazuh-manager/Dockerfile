FROM ubuntu:18.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install python git gnupg2 gcc make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python-cryptography -y
# && apt-get update && apt-get install wazuh-manager

ADD entrypoint.sh /scripts/entrypoint.sh
RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout dev-flask-poc-ciscat-endpoints

RUN sed -i 's!--index-url=file://${ROUTE_PATH}/${EXTERNAL_CPYTHON}/Dependencies/simple!!' /wazuh/src/Makefile
COPY preloaded-vars.conf /wazuh/etc/preloaded-vars.conf

RUN /wazuh/install.sh

# install pip libraries for development
RUN /var/ossec/framework/python/bin/pip3 install pytest==4.5.0 tavern pytest-cov defusedxml ptvsd pydevd-pycharm~=191.7479.30 freezegun

RUN curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add - &&\
    echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-6.x.list &&\
    apt-get update &&\
    apt-get install filebeat=6.6.0 &&\
    curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/3.9/extensions/filebeat/filebeat.yml &&\
    sed -i 's/YOUR_ELASTIC_SERVER_IP/logstash/' /etc/filebeat/filebeat.yml
