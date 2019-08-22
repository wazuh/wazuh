FROM ubuntu:18.04

ARG wazuhbranch

# install supervisor just in case it isn't already installed
RUN apt-get update && apt-get install -y openssh-server supervisor
ADD base/wazuh-manager/supervisord.conf /etc/supervisor/conf.d/

RUN apt-get update && apt-get install python git gnupg2 gcc make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python-cryptography -y && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/staging/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh.list

RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout $wazuhbranch

# ÑAPA!!! -> para evitar errores al instalar paquetes Python
RUN sed -i 's!--index-url=file://${ROUTE_PATH}/${EXTERNAL_CPYTHON}/Dependencies/simple!!' /wazuh/src/Makefile
COPY base/wazuh-manager/preloaded-vars.conf /wazuh/etc/preloaded-vars.conf

RUN /wazuh/install.sh

ADD base/wazuh-manager/entrypoint.sh /scripts/entrypoint.sh