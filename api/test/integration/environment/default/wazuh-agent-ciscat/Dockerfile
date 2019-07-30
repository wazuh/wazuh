FROM ubuntu:16.04

RUN apt-get update && apt-get update && apt-get install curl apt-transport-https lsb-release gnupg2 -y && \
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
    echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list && \
    apt-get update

RUN apt-get install openjdk-8-jre -y

RUN apt-get install wazuh-agent -y

COPY test.keys /var/ossec/etc/test.keys

COPY ossec.conf /var/ossec/etc/ossec.conf

COPY ciscat /var/ossec/wodles/ciscat

RUN cd /var/ossec/wodles/ciscat && chmod +x CIS-CAT.sh

ADD entrypoint.sh /scripts/entrypoint.sh