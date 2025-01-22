FROM ubuntu:24.04 AS builder

# Install dependencies
RUN apt-get update && apt-get install -y build-essential cmake make gcc git zip curl tar ninja-build pkg-config wget \
    gnupg lsb-release software-properties-common libbz2-dev libsystemd-dev iputils-ping

RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 18

RUN apt-get update && apt-get install -y clang-tidy-18 autopoint libtool zlib1g-dev libgcrypt20-dev libmagic-dev \
    libpopt-dev libsqlite3-dev liblua5.4-dev gettext libarchive-dev libxml2

# Clone repository and initialize submodules
RUN git clone https://github.com/wazuh/wazuh-agent.git --single-branch --depth=1

WORKDIR /wazuh-agent

RUN git submodule update --init --recursive

# Compile the binary
RUN cmake /wazuh-agent/src -B /wazuh-agent/build

RUN cmake --build /wazuh-agent/build

FROM ubuntu:24.04 AS agent

RUN apt update && apt install -y iputils-ping curl

COPY --from=builder /wazuh-agent/build/wazuh-agent /usr/share/wazuh-agent/bin/wazuh-agent

RUN mkdir -p /var/lib/wazuh-agent

ADD entrypoint.sh /scripts/entrypoint.sh

ENTRYPOINT ["/scripts/entrypoint.sh"]
