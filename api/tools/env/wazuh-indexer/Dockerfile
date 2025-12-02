FROM opensearchproject/opensearch:2.19.0

USER root

RUN yum update -y && \
    yum install -y curl unzip sudo jq yum-utils --allowerasing && \
    yum-config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo && \
    yum install -y gh && \
    yum clean all && \
    rm -rf /var/cache/yum

COPY --chown=opensearch:opensearch download_indexer.sh /usr/share/opensearch/download_indexer.sh
COPY --chown=opensearch:opensearch entrypoint.sh /usr/share/opensearch/entrypoint.sh

RUN chmod +x /usr/share/opensearch/download_indexer.sh /usr/share/opensearch/entrypoint.sh

# Allow opensearch user to run gh, mkdir, touch, chmod as root without password for setup operations
RUN echo 'opensearch ALL=(ALL) NOPASSWD: /usr/bin/gh, /bin/mkdir, /bin/touch, /bin/chmod' >> /etc/sudoers.d/opensearch && \
    chmod 0440 /etc/sudoers.d/opensearch

USER opensearch

ENTRYPOINT ["/usr/share/opensearch/entrypoint.sh"]
