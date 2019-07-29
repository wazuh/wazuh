FROM ubuntu:18.04

ARG wazuhbranch

# install supervisor just in case it isn't already installed
RUN apt-get update && apt-get install -y openssh-server supervisor

ADD supervisord.conf /etc/supervisor/conf.d/
ADD sshd.conf /etc/supervisor/conf.d/
RUN mkdir -p /var/run/sshd /var/log/supervisor

ADD id_rsa.pub ./

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

ADD entrypoint.sh /scripts/entrypoint.sh
RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout $wazuhbranch
#RUN git clone https://github.com/wazuh/wazuh-ruleset && cd /wazuh-ruleset && git checkout dev-flask-poc
# RUN cd /wazuh && git pull

# ÑAPA!!! -> para evitar errores al instalar paquetes Python
RUN sed -i 's!--index-url=file://${ROUTE_PATH}/${EXTERNAL_CPYTHON}/Dependencies/simple!!' /wazuh/src/Makefile
COPY preloaded-vars.conf /wazuh/etc/preloaded-vars.conf

RUN /wazuh/install.sh

# install pip libraries for development
RUN /var/ossec/framework/python/bin/pip3 install pytest==4.5.0 tavern pytest-cov defusedxml ptvsd pydevd-pycharm~=191.7479.30 freezegun

# instalar pydev para remote debugging
#RUN /var/ossec/framework/python/bin/pip3 install pydevd-pycharm~=191.6183.5

#RUN curl -sL https://deb.nodesource.com/setup_8.x | bash - && apt-get install -y nodejs && npm config set user 0
RUN curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add - &&\
    echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-6.x.list &&\
    apt-get update &&\
    apt-get install filebeat=6.6.0 &&\
    curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/3.9/extensions/filebeat/filebeat.yml &&\
    sed -i 's/YOUR_ELASTIC_SERVER_IP/logstash/' /etc/filebeat/filebeat.yml

#RUN apt-get update && apt-get install wazuh-api -y
