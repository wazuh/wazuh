FROM haproxytech/haproxy-ubuntu:2.7

COPY haproxy.conf /etc/haproxy/haproxy.conf

ADD entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --interval=5s --timeout=10s --retries=60 CMD curl -kfs https://localhost:55000/ || exit 1
