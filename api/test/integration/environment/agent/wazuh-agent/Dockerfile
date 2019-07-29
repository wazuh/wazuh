FROM ubuntu:18.04

RUN apt-get update && apt-get update && apt-get install curl apt-transport-https lsb-release gnupg2 -y && \
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
    echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list && \
    apt-get update

RUN apt-get install wazuh-agent -y

COPY test.keys /var/ossec/etc/test.keys

ADD entrypoint.sh /scripts/entrypoint.sh