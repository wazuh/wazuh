FROM public.ecr.aws/o5x5t0j3/amd64/api_development:integration_test_wazuh-generic

# DOCKER_COMPOSE_FILE needs to be assigned to an environment variable as it is going to be used at run time (CMD)
ARG DOCKER_COMPOSE_FILE
ENV DOCKER_COMPOSE_FILE ${DOCKER_COMPOSE_FILE}

# INSTALL MANAGER
ARG WAZUH_BRANCH

ADD base/manager/supervisord.conf /etc/supervisor/conf.d/

RUN mkdir wazuh && curl -sL https://github.com/wazuh/wazuh/tarball/${WAZUH_BRANCH} | tar zx --strip-components=1 -C wazuh
COPY base/manager/preloaded-vars.conf /wazuh/etc/preloaded-vars.conf
RUN /wazuh/install.sh

COPY base/manager/entrypoint.sh /scripts/entrypoint.sh
COPY base/manager/entrypoint_no_cluster.sh /scripts/entrypoint_no_cluster.sh

# HEALTHCHECK
HEALTHCHECK --retries=600 --interval=1s --timeout=30s --start-period=30s CMD /var/ossec/framework/python/bin/python3 /tmp/healthcheck/healthcheck.py ${DOCKER_COMPOSE_FILE} || exit 1
