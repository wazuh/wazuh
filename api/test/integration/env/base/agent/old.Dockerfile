FROM public.ecr.aws/o5x5t0j3/amd64/api_development:integration_test_wazuh-agent_old

# Configuration
COPY tools/* /tools/
COPY configurations/base/agent/configuration_files/test.keys /var/ossec/etc/test.keys
COPY configurations/tmp/agent/ /
RUN rm /configuration_files/ossec_4.x.conf

ADD base/agent/entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --retries=30 --interval=10s --timeout=30s --start-period=30s CMD /usr/bin/python3 /healthcheck/healthcheck.py || exit 1
