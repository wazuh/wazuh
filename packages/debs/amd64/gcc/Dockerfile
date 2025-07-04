FROM debian:8

RUN rm -f /etc/apt/sources.list && \
    printf 'deb [check-valid-until=no] http://archive.debian.org/debian jessie main contrib non-free\n' \
          > /etc/apt/sources.list && \
    printf 'deb [check-valid-until=no] http://archive.debian.org/debian-security jessie/updates main contrib non-free\n' \
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
ENV MAKEFLAGS="-j$(nproc)"

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
    make && make install-strip

ENV PATH=/opt/gcc-8.5.0/bin:$PATH \
    CC=/opt/gcc-8.5.0/bin/gcc \
    CXX=/opt/gcc-8.5.0/bin/g++

ARG GCC_FINAL_VER=15.1.0
RUN curl -LO https://ftp.gnu.org/gnu/gcc/gcc-${GCC_FINAL_VER}/gcc-${GCC_FINAL_VER}.tar.xz && \
    tar -xf gcc-${GCC_FINAL_VER}.tar.xz && \
    cd gcc-${GCC_FINAL_VER} && \
    ./contrib/download_prerequisites && \
    mkdir build && cd build && \
    ../configure --prefix=/opt/gcc-${GCC_FINAL_VER%%.*} \
                 --disable-multilib \
                 --enable-languages=c,c++ \
                 --with-system-zlib && \
    make -j8 && make install-strip

RUN apt-get install -y --allow-unauthenticated --no-install-recommends dpkg-dev && \
    mkdir -p /packages && \
    mkdir -p /pkgbuild/gcc15/DEBIAN && \
    printf "Package: gcc15\nVersion: 15.1-1\nSection: devel\nPriority: optional\n\
Architecture: amd64\nMaintainer: bootstrap <root@localhost>\n\
Provides: gcc, g++\nDescription: GNU Compiler Collection 15.1 built from source on Debian 8\n" \
        > /pkgbuild/gcc15/DEBIAN/control && \
    mkdir -p /pkgbuild/gcc15/opt && \
    cp -a /opt/gcc-15 /pkgbuild/gcc15/opt/ && \
    chmod 755 /pkgbuild/gcc15/DEBIAN && \
    dpkg-deb --build /pkgbuild/gcc15 /packages && \
    rm -rf /pkgbuild
