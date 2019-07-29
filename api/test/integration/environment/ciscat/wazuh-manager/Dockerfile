FROM ubuntu:18.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y supervisor

ADD supervisord.conf /etc/supervisor/conf.d/
ADD sshd.conf /etc/supervisor/conf.d/
RUN mkdir -p /var/run/sshd /var/log/supervisor

ADD id_rsa.pub ./

RUN apt-get update && apt-get install python git gnupg2 gcc make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python-cryptography -y && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/staging/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh.list

ADD entrypoint.sh /scripts/entrypoint.sh
RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout dev-flask-poc

RUN sed -i 's!--index-url=file://${ROUTE_PATH}/${EXTERNAL_CPYTHON}/Dependencies/simple!!' /wazuh/src/Makefile
COPY preloaded-vars.conf /wazuh/etc/preloaded-vars.conf

RUN /wazuh/install.sh

RUN /var/ossec/framework/python/bin/pip3 install defusedxml ptvsd
