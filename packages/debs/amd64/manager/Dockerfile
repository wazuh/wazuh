FROM debian:8

ENV DEBIAN_FRONTEND noninteractive

# Installing necessary packages
RUN echo 'Acquire::Check-Valid-Until "false";' >> /etc/apt/apt.conf && \
    echo "deb http://archive.debian.org/debian jessie contrib main non-free" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security jessie/updates main" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y --force-yes apt-utils && \
    apt-get install -y --force-yes \
    curl g++ bzip2 debhelper gcc rename make sudo wget expect gnupg perl-base perl \
    libc-bin libc6 libc6-dev build-essential dpkg-dev\
    cdbs devscripts equivs automake autoconf libtool libaudit-dev selinux-basics \
    libdb5.3 libdb5.3-dev libssl1.0.0 libssl-dev procps git gawk libsigsegv2

RUN echo "deb-src http://archive.debian.org/debian jessie contrib main non-free" >> /etc/apt/sources.list && \
    apt-get update && apt-get build-dep python3 -y --force-yes

ADD https://packages.wazuh.com/utils/gcc/gcc_14.3-1_amd64.deb /tmp/gcc_14.3-1_amd64.deb
RUN dpkg -i /tmp/gcc_14.3-1_amd64.deb && \
    ln -fs /opt/gcc-14/bin/g++ /usr/bin/c++ && \
    ln -fs /opt/gcc-14/bin/g++ /usr/bin/g++ && \
    ln -fs /opt/gcc-14/bin/gcc /usr/bin/gcc

ENV CPLUS_INCLUDE_PATH "/opt/gcc-14/include/c++/14.3.0/"
ENV LD_LIBRARY_PATH "/opt/gcc-14/lib64:${LD_LIBRARY_PATH}"
ENV PATH "/opt/gcc-14/bin:${PATH}"

ADD https://packages.wazuh.com/utils/binutils/binutils_2.38-1_amd64.deb /tmp/binutils_2.38-1_amd64.deb
RUN dpkg -i /tmp/binutils_2.38-1_amd64.deb

ENV PATH "/opt/binutils-2/bin:${PATH}"

ADD https://github.com/Kitware/CMake/releases/download/v3.30.4/cmake-3.30.4-linux-x86_64.sh /tmp/cmake-3.30.4-linux-x86_64.sh

RUN mkdir -p /opt/cmake
RUN sh /tmp/cmake-3.30.4-linux-x86_64.sh --prefix=/opt/cmake --skip-license

RUN ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake
RUN ln -s /opt/cmake/bin/ctest /usr/local/bin/ctest

# Add the script to build the Debian package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package
ADD helper_function.sh /usr/local/bin/helper_function.sh
ADD gen_permissions.sh /tmp/gen_permissions.sh

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
