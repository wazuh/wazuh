FROM dev-wazuh-base AS builder

COPY preloaded-vars.conf /wazuh/etc/preloaded-vars.conf

RUN /wazuh/install.sh

# install pip libraries for development
RUN /var/ossec/framework/python/bin/pip3 install pydevd-pycharm freezegun ipdb

FROM builder as server

COPY --from=builder /var/ossec /var/ossec

# Soft link for the embedded python
RUN ln -s /var/ossec/framework/python/bin/python3 /bin/wpy
RUN ln -s /var/ossec/framework/python/bin/pip3 /bin/wpip

ADD xml/xml_parser.py /scripts/xml_parser.py
ADD xml/master_ossec_conf.xml /scripts/master_ossec_conf.xml
ADD xml/worker_ossec_conf.xml /scripts/worker_ossec_conf.xml
ADD entrypoint.sh /scripts/entrypoint.sh
ADD healthcheck.sh /scripts/healthcheck.sh
RUN chmod +x /scripts/healthcheck.sh

HEALTHCHECK --interval=5s --timeout=30s --start-period=5s --retries=35 CMD /scripts/healthcheck.sh
