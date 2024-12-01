FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y cmake make gcc git zip curl tar ninja-build pkg-config wget gnupg lsb-release \
    software-properties-common libbz2-dev clang-tidy-18 autopoint libtool zlib1g-dev libgcrypt20-dev libmagic-dev \
    libpopt-dev libmagic-dev libsqlite3-dev liblua5.4-dev gettext libarchive-dev iputils-ping

RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 18

RUN git clone https://github.com/wazuh/wazuh-agent.git && cd wazuh-agent && git submodule update --init --recursive

RUN cmake src -B build && cmake --build build

RUN mv ./wazuh-agent /usr/share/wazuh-agent/bin/wazuh-agent

ADD entrypoint.sh /scripts/entrypoint.sh

ENTRYPOINT ["/scripts/entrypoint.sh"]

