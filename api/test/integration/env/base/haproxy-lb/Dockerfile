FROM haproxytech/haproxy-ubuntu:2.7

COPY haproxy.conf /etc/haproxy/haproxy.conf

ADD entrypoint.sh /scripts/entrypoint.sh

# Healthy once a manager API answers TLS through the balancer; GET / without a token gets a 401
HEALTHCHECK --interval=5s --timeout=10s --retries=60 CMD curl -ks -o /dev/null https://localhost:55000/ || exit 1
