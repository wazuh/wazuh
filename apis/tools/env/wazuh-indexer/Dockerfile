FROM opensearchproject/opensearch:3.0.0

COPY --chown=opensearch:opensearch . .

RUN /usr/share/opensearch/bin/opensearch-plugin install file:/usr/share/opensearch/wazuh-indexer-setup-6.0.0.0.zip

RUN /usr/share/opensearch/bin/opensearch-plugin install --batch file:/usr/share/opensearch/wazuh-indexer-command-manager-6.0.0.0.zip
