FROM haproxytech/haproxy-ubuntu:2.7

COPY haproxy.conf /etc/haproxy/haproxy.conf

ADD entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --interval=1s --timeout=3s --retries=10 CMD curl --fail http://localhost/ || exit 1
