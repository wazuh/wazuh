FROM opensearchproject/opensearch:2.19.1

COPY --chown=opensearch:opensearch . .

RUN /usr/share/opensearch/bin/opensearch-plugin install file:/usr/share/opensearch/wazuh-indexer-setup-5.0.0.0.zip

RUN /usr/share/opensearch/bin/opensearch-plugin install --batch file:/usr/share/opensearch/wazuh-indexer-command-manager-5.0.0.0.zip
