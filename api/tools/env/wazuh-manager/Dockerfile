FROM wazuh-base AS builder

COPY preloaded-vars.conf /wazuh/etc/preloaded-vars.conf
RUN THREADS=$(nproc) /wazuh/install.sh

# Install pip libraries for development
RUN /var/wazuh-manager/framework/python/bin/python3 -m pip install \
    pydevd-pycharm freezegun ipdb
# ----------------------------------------------------

FROM builder AS server

# Copy Wazuh installation
COPY --from=builder /var/wazuh-manager /var/wazuh-manager

# Embedded python symlinks
RUN ln -s /var/wazuh-manager/framework/python/bin/python3 /bin/wpy && \
    ln -s /var/wazuh-manager/framework/python/bin/pip3 /bin/wpip

ADD yml/yaml_merge.py /scripts/yaml_merge.py
ADD yml/master_wazuh-manager.yml /scripts/master_wazuh-manager.yml
ADD yml/worker_wazuh-manager.yml /scripts/worker_wazuh-manager.yml
ADD entrypoint.sh /scripts/entrypoint.sh
ADD healthcheck.sh /scripts/healthcheck.sh
RUN chmod +x /scripts/healthcheck.sh

HEALTHCHECK --interval=5s --timeout=30s --start-period=5s --retries=35 CMD /scripts/healthcheck.sh
