FROM debian:7

ENV DEBIAN_FRONTEND noninteractive

# Installing necessary packages
RUN echo "deb http://archive.debian.org/debian/ wheezy contrib main non-free" > /etc/apt/sources.list && \
    echo "deb-src http://archive.debian.org/debian/ wheezy contrib main non-free" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y --force-yes apt-utils && \
    apt-get install -y --force-yes \
    curl gcc make sudo wget expect gnupg perl-base=5.14.2-21+deb7u3 perl \
    libc-bin=2.13-38+deb7u10 libc6=2.13-38+deb7u10 libc6-dev build-essential \
    cdbs devscripts equivs automake autoconf libtool libaudit-dev selinux-basics \
    libdb5.1=5.1.29-5 libdb5.1-dev libssl1.0.0=1.0.1e-2+deb7u20 procps gawk libsigsegv2

RUN apt-get update && apt-get build-dep python3.2 -y --force-yes

RUN curl -OL http://packages.wazuh.com/utils/gcc/gcc-9.4.0.tar.gz && \
    tar xzf gcc-9.4.0.tar.gz  && cd gcc-9.4.0/ && \
    ./contrib/download_prerequisites && \
    ./configure --prefix=/usr/local/gcc-9.4.0 --enable-languages=c,c++ --disable-multilib \
        --disable-libsanitizer && \
    make -j$(nproc) && make install && \
    ln -fs /usr/local/gcc-9.4.0/bin/g++ /usr/bin/c++ && \
    ln -fs /usr/local/gcc-9.4.0/bin/gcc /usr/bin/cc && cd / && rm -rf gcc-*

ENV CPLUS_INCLUDE_PATH "/usr/local/gcc-9.4.0/include/c++/9.4.0/"
ENV LD_LIBRARY_PATH "/usr/local/gcc-9.4.0/lib64:${LD_LIBRARY_PATH}"
ENV PATH "/usr/local/gcc-9.4.0/bin:${PATH}"

RUN curl -OL http://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz && \
    tar -zxf cmake-3.18.3.tar.gz && cd cmake-3.18.3 && \
    ./bootstrap --no-system-curl CXX=/usr/local/gcc-9.4.0/bin/g++ \
        CC=/usr/local/gcc-9.4.0/bin/gcc && \
    make -j$(nproc) && make install && ln -s /usr/local/bin/cmake /usr/bin/cmake && \
    cd / && rm -rf cmake-*

# Add the script and helper_funcitons to build the Debian package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package
ADD helper_function.sh /usr/local/bin/helper_function.sh
ADD gen_permissions.sh /tmp/gen_permissions.sh

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
