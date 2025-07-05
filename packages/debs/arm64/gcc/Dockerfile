FROM arm64v8/debian:9

ARG GCC_MAJOR_VERSION=14
ARG GCC_MINOR_VERSION=3

RUN rm -f /etc/apt/sources.list && \
    printf 'deb [check-valid-until=no] http://archive.debian.org/debian stretch main contrib non-free\n' \
          > /etc/apt/sources.list && \
    printf 'deb [check-valid-until=no] http://archive.debian.org/debian-security stretch/updates main contrib non-free\n' \
          >> /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/90no-check-valid

RUN apt-get -o Acquire::AllowInsecureRepositories=true \
           -o Acquire::Check-Valid-Until=false update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --allow-unauthenticated --no-install-recommends \
        build-essential curl ca-certificates \
        bzip2 xz-utils git make flex texinfo \
        libgmp-dev libmpfr-dev libmpc-dev zlib1g-dev \
        ruby ruby-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

ARG GCC_STAGE1_VER=8.5.0
RUN curl -LO https://ftp.gnu.org/gnu/gcc/gcc-${GCC_STAGE1_VER}/gcc-${GCC_STAGE1_VER}.tar.xz && \
    tar -xf gcc-${GCC_STAGE1_VER}.tar.xz && \
    cd gcc-${GCC_STAGE1_VER} && \
    ./contrib/download_prerequisites && \
    mkdir build && cd build && \
    ../configure --prefix=/opt/gcc-${GCC_STAGE1_VER} \
                 --disable-multilib \
                 --enable-languages=c,c++ \
                 --with-system-zlib \
                 --disable-bootstrap && \
    make -j2 && make install-strip

ENV PATH=/opt/gcc-8.5.0/bin:$PATH \
    CC=/opt/gcc-8.5.0/bin/gcc \
    CXX=/opt/gcc-8.5.0/bin/g++

RUN curl -LO https://ftp.gnu.org/gnu/gcc/gcc-${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION}.0/gcc-${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION}.0.tar.xz && \
    tar -xf gcc-${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION}.0.tar.xz && \
    cd gcc-${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION}.0 && \
    ./contrib/download_prerequisites && \
    mkdir build && cd build && \
    ../configure --prefix=/opt/gcc-${GCC_MAJOR_VERSION} \
                 --disable-multilib \
                 --enable-default-dwarf=2 \
                 --enable-languages=c,c++ \
                 --with-system-zlib && \
    make -j2 && make install-strip

RUN apt-get install -y --allow-unauthenticated --no-install-recommends dpkg-dev && \
    mkdir -p /packages && \
    mkdir -p /pkgbuild/gcc${GCC_MAJOR_VERSION}/DEBIAN && \
    printf "Package: gcc${GCC_MAJOR_VERSION}\nVersion: ${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION}-1\nSection: devel\nPriority: optional\n\
Architecture: arm64\nMaintainer: bootstrap <root@localhost>\n\
Provides: gcc, g++\nDescription: GNU Compiler Collection ${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION} built from source on Debian 9\n" \
        > /pkgbuild/gcc${GCC_MAJOR_VERSION}/DEBIAN/control && \
    mkdir -p /pkgbuild/gcc${GCC_MAJOR_VERSION}/opt && \
    cp -a /opt/gcc-${GCC_MAJOR_VERSION} /pkgbuild/gcc${GCC_MAJOR_VERSION}/opt/ && \
    chmod 755 /pkgbuild/gcc${GCC_MAJOR_VERSION}/DEBIAN && \
    dpkg-deb --build /pkgbuild/gcc${GCC_MAJOR_VERSION} /packages && \
    rm -rf /pkgbuild