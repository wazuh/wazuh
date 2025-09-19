FROM debian:7

ENV DEBIAN_FRONTEND noninteractive
# -------------------------------------------------------------------
# Install necessary packages
# -------------------------------------------------------------------
RUN echo "deb http://archive.debian.org/debian/ wheezy contrib main non-free" > /etc/apt/sources.list && \
    echo "deb-src http://archive.debian.org/debian/ wheezy contrib main non-free" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y --force-yes apt-utils && \
    apt-get install -y --force-yes \
    curl gcc make sudo wget expect gnupg perl-base=5.14.2-21+deb7u3 perl \
    libc-bin=2.13-38+deb7u10 libc6=2.13-38+deb7u10 libc6-dev build-essential \
    cdbs devscripts equivs automake autoconf libtool libaudit-dev selinux-basics \
    libdb5.1=5.1.29-5 libdb5.1-dev libssl1.0.0=1.0.1e-2+deb7u20 procps gawk libsigsegv2

RUN apt-get update && apt-get build-dep python3.2 -y --force-yes && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------
# Install certificates for https
# -------------------------------------------------------------------
COPY certificates/cacert.pem /etc/ssl/certs/ca-certificates.crt

ENV CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# -------------------------------------------------------------------
# CMake
# -------------------------------------------------------------------
RUN curl -LO https://github.com/Kitware/CMake/releases/download/v3.22.0/cmake-3.22.0-Linux-x86_64.sh && \
    bash cmake-3.22.0-Linux-x86_64.sh --skip-license --prefix=/usr/local && \
    rm -f cmake-3.22.0-Linux-x86_64.sh

# -------------------------------------------------------------------
# GCC 9.4.0 (bootstrap only)
# -------------------------------------------------------------------
RUN curl -OL http://packages.wazuh.com/utils/gcc/gcc-9.4.0.tar.gz && \
    tar xzf gcc-9.4.0.tar.gz && cd gcc-9.4.0 && \
    ./contrib/download_prerequisites && \
    ./configure --prefix=/usr/local/gcc-9.4.0 \
        --enable-languages=c,c++ \
        --disable-multilib \
        --disable-bootstrap \
        --disable-libsanitizer && \
    make -j$(nproc) && make install && \
    cd / && rm -rf gcc-9.4.0*

# -------------------------------------------------------------------
# GCC 14.3.0 (set as final compiler)
# -------------------------------------------------------------------
RUN curl -OL https://ftp.fu-berlin.de/unix/languages/gcc/releases/gcc-14.3.0/gcc-14.3.0.tar.gz && \
    tar xzf gcc-14.3.0.tar.gz && cd gcc-14.3.0 && ./contrib/download_prerequisites && \
    mkdir build && cd build && \
    CC=/usr/local/gcc-9.4.0/bin/gcc \
    CXX=/usr/local/gcc-9.4.0/bin/g++ \
    ../configure --prefix=/usr/local/gcc-14.3.0 \
        --enable-languages=c,c++ \
        --disable-multilib \
        --disable-libsanitizer \
        --disable-bootstrap && \
    make -j$(nproc) && make install && \
    cd / && rm -rf gcc-14.3.0* && \
    rm -rf /usr/local/gcc-9.4.0   # limpiar bootstrap

# -------------------------------------------------------------------
# Environment variables → only GCC 14.3
# -------------------------------------------------------------------
ENV PATH="/usr/local/gcc-14.3.0/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/gcc-14.3.0/lib64"
ENV CC="/usr/local/gcc-14.3.0/bin/gcc"
ENV CXX="/usr/local/gcc-14.3.0/bin/g++"

# -------------------------------------------------------------------
# Add the script and helper_functions to build the Debian package
# -------------------------------------------------------------------
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package
ADD helper_function.sh /usr/local/bin/helper_function.sh
ADD gen_permissions.sh /tmp/gen_permissions.sh

# -------------------------------------------------------------------
# Set entrypoint
# -------------------------------------------------------------------
ENTRYPOINT ["/usr/local/bin/build_package"]
