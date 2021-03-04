FROM public.ecr.aws/o5x5t0j3/amd64/api_development:integration_test_wazuh-generic

ARG WAZUH_BRANCH

## install Wazuh
RUN git clone https://github.com/wazuh/wazuh -b $WAZUH_BRANCH --depth=1
ADD base/agent/preloaded-vars.conf /wazuh/etc/preloaded-vars.conf
RUN /wazuh/install.sh

COPY tools/* /tools/
COPY configurations/base/agent/configuration_files/test.keys /var/ossec/etc/test.keys
COPY configurations/tmp/agent/ /

ADD base/agent/entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --retries=30 --interval=10s --timeout=30s --start-period=30s CMD /usr/bin/python3 /healthcheck/healthcheck.py || exit 1
