FROM ubuntu:24.04 AS builder

ENV LANG=en_US.utf8
ENV TZ=America/New_York
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y locales && rm -rf /var/lib/apt/lists/* \
	&& localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Install dependencies
RUN apt update && apt install -y \
    build-essential \
    pkg-config \
    clang-format \
    cmake \
    git \
    python3 \
    python3-pip \
    curl \
    zip \
    lzip \
    unzip \
    tar \
    wget

# Install vcpkg
ENV VCPKG_ROOT=/root/vcpkg

RUN git clone "https://github.com/microsoft/vcpkg.git" $VCPKG_ROOT \
    && cd $VCPKG_ROOT \
    && ./bootstrap-vcpkg.sh \
    && echo "export VCPKG_ROOT=$VCPKG_ROOT" >> ~/.bashrc \
    && echo "export PATH=\$PATH:\$VCPKG_ROOT" >> ~/.bashrc

# Install CMake
ENV CMAKE_VERSION="3.30.5"

COPY scripts/reinstall-cmake.sh /tmp/reinstall-cmake.sh

RUN chmod +x /tmp/reinstall-cmake.sh && /tmp/reinstall-cmake.sh ${CMAKE_VERSION}

# Build and install wazuh-server
ENV WAZUH_BRANCH=master
ENV WAZUH_ROOT=/root/wazuh
ENV ENGINE_PRESET=release
ENV ENGINE_ON_BACKGROUND=1

COPY scripts/build.sh /tmp/build.sh

RUN /tmp/build.sh

FROM ubuntu:24.04 AS wazuh-server

COPY --from=builder /usr/share/wazuh-server /usr/share/wazuh-server

RUN apt update && apt install -y vim curl apt-transport-https sqlite3

COPY scripts/entrypoint.sh /scripts/entrypoint.sh

COPY scripts/healthcheck.sh /scripts/healthcheck.sh

HEALTHCHECK --interval=5s --timeout=30s --start-period=5s --retries=35 CMD /scripts/healthcheck.sh
