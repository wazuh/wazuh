FROM arm64v8/debian:stretch

ENV DEBIAN_FRONTEND noninteractive

# -------------------------------------------------------------------
# Install necessary packages
# -------------------------------------------------------------------
RUN echo "deb http://archive.debian.org/debian stretch contrib main non-free" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security stretch/updates main" >> /etc/apt/sources.list && \
    echo "deb-src http://archive.debian.org/debian stretch main" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y --allow-change-held-packages apt apt-utils  \
    curl gcc g++ make sudo expect gnupg procps \
    perl-base perl wget libc-bin libc6 libc6-dev \
    build-essential cdbs devscripts equivs automake \
    autoconf libtool libaudit-dev selinux-basics \
    libdb5.3 libssl1.0.2 libssl-dev gawk libsigsegv2 \
    libgmp-dev libmpfr-dev libmpc-dev libisl-dev

# -------------------------------------------------------------------
# CMake
# -------------------------------------------------------------------
RUN curl -LO https://github.com/Kitware/CMake/releases/download/v3.22.0/cmake-3.22.0-Linux-aarch64.sh && \
    bash cmake-3.22.0-Linux-aarch64.sh --skip-license --prefix=/usr/local && \
    rm -f cmake-3.22.0-Linux-aarch64.sh

# -------------------------------------------------------------------
# GCC 14.3.0 (set as final compiler)
# -------------------------------------------------------------------
RUN curl -OL https://ftp.fu-berlin.de/unix/languages/gcc/releases/gcc-14.3.0/gcc-14.3.0.tar.gz && \
    tar xzf gcc-14.3.0.tar.gz && cd gcc-14.3.0 && \
    mkdir build && cd build && \
    ../configure --prefix=/usr/local/gcc-14.3.0 \
        --enable-languages=c,c++ \
        --disable-multilib \
        --disable-libsanitizer \
        --disable-bootstrap && \
    make -j$(nproc) && make install && \
    cd / && rm -rf gcc-14.3.0* && \
    apt remove -y gcc g++

# -------------------------------------------------------------------
# Environment variables → only GCC 14.3
# -------------------------------------------------------------------
ENV PATH="/usr/local/gcc-14.3.0/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/gcc-14.3.0/lib64"
ENV CC="/usr/local/gcc-14.3.0/bin/gcc"
ENV CXX="/usr/local/gcc-14.3.0/bin/g++"

# -------------------------------------------------------------------
# Add the script to build the Debian package
# -------------------------------------------------------------------
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package
ADD helper_function.sh /usr/local/bin/helper_function.sh
ADD gen_permissions.sh /tmp/gen_permissions.sh

# -------------------------------------------------------------------
# Set the entrypoint
# -------------------------------------------------------------------
ENTRYPOINT ["/usr/local/bin/build_package"]
