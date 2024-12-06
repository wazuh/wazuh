FROM public.ecr.aws/o5x5t0j3/amd64/api_development:integration_test_wazuh-agent_old

COPY base/agent/entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --retries=900 --interval=1s --timeout=40s --start-period=30s CMD /usr/bin/python3 /tmp_volume/healthcheck/legacy_healthcheck.py || exit 1
