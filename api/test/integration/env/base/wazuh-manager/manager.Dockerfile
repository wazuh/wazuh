ARG ENVIRONMENT

FROM ubuntu:18.04 AS base

ARG wazuhbranch

RUN apt-get update && apt-get install -y supervisor
ADD base/wazuh-manager/supervisord.conf /etc/supervisor/conf.d/

RUN apt-get update && apt-get install python git gnupg2 gcc make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python-cryptography sqlite3 -y && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/staging/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh.list

RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout $wazuhbranch
COPY base/wazuh-manager/preloaded-vars.conf /wazuh/etc/preloaded-vars.conf
RUN /wazuh/install.sh
RUN sed -i 's,"mode": \("white"\|"black"\),"mode": "black",g' /var/ossec/framework/python/lib/python3.7/site-packages/api-4.0.0-py3.7.egg/api/configuration.py
###
ADD base/wazuh-manager/entrypoint.sh /scripts/entrypoint.sh

FROM base AS wazuh-env-base

FROM base AS wazuh-env-agents
COPY configurations/agents/test_custom_upgrade_3.10.2.wpk /var/ossec/test_custom_upgrade_3.10.2.wpk

FROM base AS wazuh-env-sca
FROM base AS wazuh-env-syscheck
FROM base AS wazuh-env-ciscat
FROM base AS wazuh-env-syscollector

FROM base as wazuh-env-rules_white_rbac
FROM base as wazuh-env-rules_black_rbac
FROM base as wazuh-env-decoders_white_rbac
FROM base as wazuh-env-decoders_black_rbac
FROM base AS wazuh-env-syscollector_white_rbac
FROM base AS wazuh-env-syscollector_black_rbac
FROM base AS wazuh-env-overview_white_rbac
FROM base AS wazuh-env-overview_black_rbac
FROM base as wazuh-env-lists_white_rbac
FROM base as wazuh-env-lists_black_rbac
FROM base AS wazuh-env-syscheck_white_rbac
FROM base AS wazuh-env-syscheck_black_rbac

FROM base AS wazuh-env-security
COPY configurations/security/wazuh-master/schema_security_test.sql /var/ossec/api/configuration/security/schema_security_test.sql
RUN sqlite3 /var/ossec/api/configuration/security/rbac.db < /var/ossec/api/configuration/security/schema_security_test.sql

FROM base AS wazuh-env-manager
ADD configurations/manager/wazuh-manager/entrypoint.sh /scripts/entrypoint.sh

FROM base AS wazuh-env-cluster
COPY configurations/cluster/wazuh-manager/ossec-totals-27.log /var/ossec/stats/totals/2019/Aug/ossec-totals-27.log
ADD configurations/cluster/wazuh-manager/entrypoint.sh /scripts/entrypoint.sh

FROM base as wazuh-env-security_white_rbac
COPY configurations/security/wazuh-master/schema_security_test.sql /var/ossec/api/configuration/security/schema_security_test.sql
RUN sqlite3 /var/ossec/api/configuration/security/rbac.db < /var/ossec/api/configuration/security/schema_security_test.sql
ADD configurations/rbac/security/white_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM base as wazuh-env-security_black_rbac
COPY configurations/security/wazuh-master/schema_security_test.sql /var/ossec/api/configuration/security/schema_security_test.sql
RUN sqlite3 /var/ossec/api/configuration/security/rbac.db < /var/ossec/api/configuration/security/schema_security_test.sql
ADD configurations/rbac/security/black_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM wazuh-env-agents as wazuh-env-agents_white_rbac
ADD configurations/rbac/agents/white_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM wazuh-env-agents as wazuh-env-agents_black_rbac
ADD configurations/rbac/agents/black_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM base as wazuh-env-ciscat_white_rbac
ADD configurations/rbac/ciscat/white_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM base as wazuh-env-ciscat_black_rbac
ADD configurations/rbac/ciscat/black_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM base as wazuh-env-sca_white_rbac
ADD configurations/rbac/sca/white_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM base as wazuh-env-sca_black_rbac
ADD configurations/rbac/sca/black_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM base as wazuh-env-active-response_white_rbac
ADD configurations/rbac/active-response/white_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM base as wazuh-env-active-response_black_rbac
ADD configurations/rbac/active-response/black_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM wazuh-env-manager as wazuh-env-manager_white_rbac
FROM wazuh-env-manager as wazuh-env-manager_black_rbac

FROM wazuh-env-cluster AS wazuh-env-cluster_white_rbac
ADD configurations/rbac/cluster/white_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM wazuh-env-cluster AS wazuh-env-cluster_black_rbac
ADD configurations/rbac/cluster/black_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM base AS wazuh-env-experimental_black_rbac
ADD configurations/rbac/experimental/black_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM base AS wazuh-env-experimental_white_rbac
ADD configurations/rbac/experimental/white_configuration_rbac.sh /scripts/configuration_rbac.sh
RUN /scripts/configuration_rbac.sh

FROM wazuh-env-${ENVIRONMENT}
