FROM i386/debian:7

ENV DEBIAN_FRONTEND noninteractive

# Installing necessary packages
RUN echo "deb http://archive.debian.org/debian/ wheezy contrib main non-free" > /etc/apt/sources.list && \
    echo "deb-src http://archive.debian.org/debian/ wheezy contrib main non-free" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y --force-yes apt-utils && \
    apt-get install -y --force-yes \
    curl gcc-multilib make wget sudo expect gnupg perl-base=5.14.2-21+deb7u3 \
    perl libc-bin=2.13-38+deb7u10 libc6=2.13-38+deb7u10 libc6-dev \
    build-essential cdbs devscripts equivs automake autoconf libtool \
    libaudit-dev selinux-basics util-linux libdb5.1=5.1.29-5 libdb5.1-dev \
    libssl1.0.0=1.0.1e-2+deb7u20 gawk libsigsegv2 procps

# Add Debian's source repository
RUN apt-get update && apt-get build-dep python3.2 -y --force-yes
RUN sed -i "s;/\* To add :#define SO_REUSEPORT 15 \*/;#define SO_REUSEPORT 15;g" /usr/include/asm-generic/socket.h

RUN curl -OL http://packages.wazuh.com/utils/gcc/gcc-9.4.0.tar.gz && \
    tar xzf gcc-9.4.0.tar.gz  && cd gcc-9.4.0/ && \
    linux32 ./contrib/download_prerequisites && \
    linux32 ./configure --prefix=/usr/local/gcc-9.4.0 --enable-languages=c,c++ \
        --disable-multilib --disable-libsanitizer && \
    linux32 make -j$(nproc) && linux32 make install && \
    ln -fs /usr/local/gcc-9.4.0/bin/g++ /usr/bin/c++ && \
    ln -fs /usr/local/gcc-9.4.0/bin/gcc /usr/bin/cc && cd / && rm -rf gcc-*

ENV CPLUS_INCLUDE_PATH "/usr/local/gcc-9.4.0/include/c++/9.4.0/"
ENV LD_LIBRARY_PATH "/usr/local/gcc-9.4.0/lib:${LD_LIBRARY_PATH}"
ENV PATH "/usr/local/gcc-9.4.0/bin:${PATH}"

RUN curl -OL http://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz && \
    tar -zxvf cmake-3.18.3.tar.gz && cd cmake-3.18.3 && \
    linux32 ./bootstrap --no-system-curl CXX=/usr/local/gcc-9.4.0/bin/g++ \
        CC=/usr/local/gcc-9.4.0/bin/gcc && \
    linux32 make -j$(nproc) && linux32 make install && \
    ln -s /usr/local/bin/cmake /usr/bin/cmake && cd / && rm -rf cmake-*

# Add the script to build the Debian package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package
ADD helper_function.sh /usr/local/bin/helper_function.sh
ADD gen_permissions.sh /tmp/gen_permissions.sh

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
