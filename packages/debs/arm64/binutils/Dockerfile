FROM arm64v8/debian:9

ARG BINUTILS_MAJOR_VERSION=2
ARG BINUTILS_MINOR_VERSION=39

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
        zlib1g-dev \
        ruby ruby-dev bison && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
ENV MAKEFLAGS="-j$(nproc)"

RUN curl -LO https://ftp.gnu.org/gnu/binutils/binutils-${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION}.tar.xz && \
    tar -xf binutils-${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION}.tar.xz && \
    cd binutils-${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION} && \
    mkdir build && cd build && \
    ../configure --prefix=/opt/binutils-${BINUTILS_MAJOR_VERSION} \
                 --disable-gprofng && \
    make -j$(nproc) && make install-strip

RUN apt-get install -y --allow-unauthenticated --no-install-recommends dpkg-dev && \
    mkdir -p /packages && \
    mkdir -p /pkgbuild/binutils${BINUTILS_MAJOR_VERSION}/DEBIAN && \
    printf "Package: binutils${BINUTILS_MAJOR_VERSION}\nVersion: ${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION}-1\nSection: devel\nPriority: optional\n\
Architecture: arm64\nMaintainer: bootstrap <root@localhost>\n\
Provides: binutils\nDescription: GNU Binary Utilities ${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION} built from source on Debian 9\n" \
        > /pkgbuild/binutils${BINUTILS_MAJOR_VERSION}/DEBIAN/control && \
    mkdir -p /pkgbuild/binutils${BINUTILS_MAJOR_VERSION}/opt && \
    cp -a /opt/binutils-${BINUTILS_MAJOR_VERSION} /pkgbuild/binutils${BINUTILS_MAJOR_VERSION}/opt/ && \
    chmod 755 /pkgbuild/binutils${BINUTILS_MAJOR_VERSION}/DEBIAN && \
    dpkg-deb --build /pkgbuild/binutils${BINUTILS_MAJOR_VERSION} /packages && \
    rm -rf /pkgbuild