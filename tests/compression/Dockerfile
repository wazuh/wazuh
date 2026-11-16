FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential cmake curl ca-certificates git python3 zstd libfaketime \
    libssl-dev libpcre2-dev libcurl4-openssl-dev libsqlite3-dev libevent-dev \
    libdb-dev libcap-dev liblzma-dev libbz2-dev libsystemd-dev clang llvm \
    libelf-dev pkg-config autoconf automake libtool libnghttp2-dev libpopt-dev \
    libudev-dev libmagic-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /wazuh
COPY . .
ARG JOBS=4
RUN make -C src TARGET=server deps -j${JOBS} && make -C src TARGET=server -j${JOBS}
RUN cd src && make TARGET=server -f Makefile -f ../tests/compression/Makefile compression-test-driver -j${JOBS}
RUN python3 tests/compression/test_docker.py && python3 tests/compression/test_daemon.py
CMD ["bash"]
