FROM ubuntu:22.04

ARG WAZUH_BRANCH

## install Wazuh
RUN mkdir wazuh && curl -sL https://github.com/wazuh/wazuh/tarball/${WAZUH_BRANCH} | tar zx --strip-components=1 -C wazuh
ADD base/agent/preloaded-vars.conf /wazuh/etc/preloaded-vars.conf
RUN /wazuh/install.sh

COPY base/agent/entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --retries=900 --interval=1s --timeout=40s --start-period=30s CMD /usr/bin/python3 /tmp_volume/healthcheck/healthcheck.py || exit 1
