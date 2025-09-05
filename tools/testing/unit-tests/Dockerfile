FROM ubuntu:22.04

ARG CMOCKA_BRANCH=stable-1.1

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y git curl make cmake gcc g++ gcc-mingw-w64-i686 g++-mingw-w64-i686 nsis libcmocka-dev clang-tools python3 lcov wine32 cppcheck astyle valgrind && \
    rm -rf /var/lib/apt/lists/* && \
    git clone -b ${CMOCKA_BRANCH} https://git.cryptomilk.org/projects/cmocka.git /root/cmocka && \
    sed -Ei 's/(BUILD_SHARED_LIBS .+) ON/\1 OFF/' /root/cmocka/DefineOptions.cmake && \
    cmake -B /root/cmocka/build -DCMAKE_C_COMPILER=i686-w64-mingw32-gcc -DCMAKE_C_LINK_EXECUTABLE=i686-w64-mingw32-ld -DCMAKE_INSTALL_PREFIX=/usr/i686-w64-mingw32/ -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_BUILD_TYPE=Release /root/cmocka && \
    cmake --build /root/cmocka/build && \
    cmake --install /root/cmocka/build && \
    rm -r /root/cmocka && \
    git config --global advice.detachedHead false

WORKDIR /src
