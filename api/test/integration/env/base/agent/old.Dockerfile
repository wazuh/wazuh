FROM base_integration_test_agent_old

# Configuration
COPY scripts/xml_parser.py /scripts/
COPY configurations/base/agent/config/ossec.conf /scripts/xml_templates/
COPY configurations/base/agent/config/ossec_4.x.conf /scripts/xml_templates/
COPY configurations/base/agent/config/test.keys /var/ossec/etc/test.keys
COPY configurations/tmp/agent/ /configuration_files/

ADD base/agent/entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --retries=30 --interval=10s --timeout=30s --start-period=30s CMD /usr/bin/python3 /configuration_files/healthcheck/healthcheck.py || exit 1
