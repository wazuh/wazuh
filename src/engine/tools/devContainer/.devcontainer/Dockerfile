FROM mcr.microsoft.com/devcontainers/cpp:1-ubuntu-24.04

ARG REINSTALL_CMAKE_VERSION_FROM_SOURCE="3.30.5"
ARG CLANG_FORMAT_REF="llvmorg-22.1.4"

# Optionally install the cmake for vcpkg
COPY ./reinstall-cmake.sh /tmp/

RUN if [ "${REINSTALL_CMAKE_VERSION_FROM_SOURCE}" != "none" ]; then \
        chmod +x /tmp/reinstall-cmake.sh && /tmp/reinstall-cmake.sh ${REINSTALL_CMAKE_VERSION_FROM_SOURCE}; \
    fi \
    && rm -f /tmp/reinstall-cmake.sh

# Build and install clang-format from source
COPY ./reinstall-clang-format.sh /tmp/
RUN apt-get update && apt-get -y install --no-install-recommends ninja-build \
    && chmod +x /tmp/reinstall-clang-format.sh \
    && /tmp/reinstall-clang-format.sh "${CLANG_FORMAT_REF}" \
    && rm -f /tmp/reinstall-clang-format.sh

# [Optional] Uncomment this section to install additional vcpkg ports.
# RUN su vscode -c "${VCPKG_ROOT}/vcpkg install <your-port-name-here>"

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends lcov docker-compose bc jq \
        inetutils-ping inetutils-telnet inetutils-tools nmap \
        libc6-dev curl policycoreutils automake autoconf libtool libssl-dev procps \
        gcc-14 g++-14 rocksdb-tools

# Set gcc-14 and g++-14 as default
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 14 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 14

# Install cmoka
 RUN git clone https://git.cryptomilk.org/projects/cmocka.git \
    && cd cmocka && git checkout stable-1.1 \
    && mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release .. && make && make install \
    && ldconfig

# The wrapper should be fix and not this fix
RUN sed -i '19i#include <stdint.h>' /usr/local/include/cmocka.h

# Install mdbook
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install mdbook
RUN cargo install mdbook-mermaid
