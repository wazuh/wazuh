FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates git \
      dpkg-dev debhelper-compat dh-python \
      python3 python3-venv python3-pip \
    && rm -rf /var/lib/apt/lists/*

COPY build.sh /usr/local/bin/build.sh
RUN chmod +x /usr/local/bin/build.sh

ENTRYPOINT ["/usr/local/bin/build.sh"]
