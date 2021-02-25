FROM public.ecr.aws/o5x5t0j3/amd64/api_development:integration_test_wazuh-generic

ARG WAZUH_BRANCH

## install Wazuh
RUN git clone https://github.com/wazuh/wazuh -b $WAZUH_BRANCH --depth=1
ADD base/agent/preloaded-vars.conf /wazuh/etc/preloaded-vars.conf
RUN /wazuh/install.sh

COPY scripts/xml_parser.py /scripts/
COPY configurations/base/agent/config/ossec.conf /scripts/xml_templates/
COPY configurations/base/agent/config/ossec_4.x.conf /scripts/xml_templates/
COPY configurations/base/agent/config/test.keys /var/ossec/etc/test.keys
COPY configurations/tmp/agent/ /configuration_files/

ADD base/agent/entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --retries=30 --interval=10s --timeout=30s --start-period=30s CMD /usr/bin/python3 /configuration_files/healthcheck/healthcheck.py || exit 1
