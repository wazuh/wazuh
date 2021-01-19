FROM ubuntu:18.04 AS base

# INSTALL MANAGER
ARG manager_branch

RUN apt-get update && apt-get install -y supervisor
ADD base/manager/supervisord.conf /etc/supervisor/conf.d/

RUN apt-get update && apt-get install wget python python3 git gnupg2 gcc make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python-cryptography sqlite3 -y && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/staging/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh.list

RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout $manager_branch
COPY base/manager/preloaded-vars.conf /wazuh/etc/preloaded-vars.conf
RUN /wazuh/install.sh

# SET CONFIGURATION FILES
COPY scripts/ /scripts/
COPY --chown=ossec:ossec configurations/base/manager/config/ /var/ossec/
COPY configurations/base/manager/configuration_files/ /configuration_files/
COPY configurations/tmp/manager/ /configuration_files/
COPY base/manager/entrypoint.sh /scripts/entrypoint.sh

ARG manager_type
RUN if [ "$manager_type" = "master" ]; then \
        cp -rf /configuration_files/master_only/config/* /var/ossec/; \
    fi

# HEALTHCHECK
HEALTHCHECK --retries=30 --interval=10s --timeout=30s --start-period=30s CMD /usr/bin/python3 /configuration_files/healthcheck/healthcheck.py || exit 1
