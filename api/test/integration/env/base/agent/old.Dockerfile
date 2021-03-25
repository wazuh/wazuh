FROM public.ecr.aws/o5x5t0j3/amd64/api_development:integration_test_wazuh-agent_old

COPY base/agent/entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --retries=30 --interval=10s --timeout=30s --start-period=30s CMD /usr/bin/python3 /tmp/healthcheck/healthcheck.py || exit 1
