ARG ENVIRONMENT

FROM ubuntu:16.04 as base_agent

ARG agent_branch

# install dependencies
RUN apt-get update && apt-get install tree python python3 git gnupg2 gcc make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python-cryptography sqlite3 build-essential openjdk-8-jre -y && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/staging/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh.list

## install Wazuh
RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout $agent_branch
ADD base/agent/preloaded-vars.conf /wazuh/etc/preloaded-vars.conf
RUN /wazuh/install.sh

COPY scripts/xml_parser.py /scripts/
COPY configurations/base/agent/config/ossec.conf /scripts/xml_templates/
COPY configurations/base/agent/config/ossec_4.x.conf /scripts/xml_templates/
COPY configurations/base/agent/config/test.keys /var/ossec/etc/test.keys
COPY configurations/tmp/agent/ /configuration_files/

ADD base/agent/entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --retries=30 --interval=10s --timeout=30s --start-period=30s CMD /usr/bin/python3 /configuration_files/healthcheck/healthcheck.py || exit 1
