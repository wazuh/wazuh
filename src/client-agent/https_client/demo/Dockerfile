# Wazuh agent HTTPS client — self-contained demo image.
# Copyright (C) 2015, Wazuh Inc.
#
# Compiles the REAL https_client module sources into a shared library against
# the distro's libcurl + OpenSSL (no full Wazuh build needed), builds the demo
# driver against it, and runs the driver at a local python TLS mock manager so
# the whole HTTPS + AES-CMAC conversation is visible. Demo harness only.
#
# Build context is staged by docker-run.sh (module sources + a handful of
# header-only deps). See that script.

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ gcc libc6-dev libcurl4-openssl-dev libssl-dev python3 openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY https_client /build/https_client
COPY deps /build/deps

RUN mkdir -p /demo && \
    g++ -std=c++17 -fPIC -shared -O2 -Wall \
        -I https_client/include -I https_client/src -I deps \
        https_client/src/*.cpp \
        -lcurl -lssl -lcrypto -lpthread \
        -o /demo/libhttps_client.so && \
    gcc -std=c11 -Wall \
        -I https_client/include -I deps \
        https_client/demo/demo_driver.c \
        -L /demo -lhttps_client -Wl,-rpath,/demo \
        -o /demo/demo_driver

COPY https_client/demo/mock_manager.py /demo/mock_manager.py
COPY https_client/demo/docker-entrypoint.sh /demo/entrypoint.sh
RUN chmod +x /demo/entrypoint.sh

CMD ["/demo/entrypoint.sh"]
