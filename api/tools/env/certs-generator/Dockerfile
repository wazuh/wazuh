FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /tmp

RUN apt-get update && apt-get install -y \
    bash \
    wget \
    openssl \
    ca-certificates \
    tar \
 && rm -rf /var/lib/apt/lists/*

RUN wget https://packages.wazuh.com/4.14/wazuh-certs-tool.sh \
    && chmod +x wazuh-certs-tool.sh

COPY config.yml /tmp/config.yml
COPY generate_certs.sh /tmp/generate_certs.sh

RUN chmod +x /tmp/generate_certs.sh

ENTRYPOINT ["/tmp/generate_certs.sh"]
