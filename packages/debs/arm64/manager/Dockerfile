FROM arm64v8/debian:stretch

ENV DEBIAN_FRONTEND noninteractive

# Installing necessary packages
RUN echo "deb http://archive.debian.org/debian stretch contrib main non-free" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security stretch/updates main" >> /etc/apt/sources.list && \
    echo "deb-src http://archive.debian.org/debian stretch main" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y --allow-change-held-packages apt apt-utils  \
    curl gcc g++ make sudo expect gnupg \
    perl-base perl wget libc-bin libc6 libc6-dev \
    build-essential cdbs devscripts equivs automake \
    autoconf libtool libaudit-dev selinux-basics \
    libdb5.3 libdb5.3 libssl1.0.2 gawk libsigsegv2

# Add Debian's source repository and, Install NodeJS 12
RUN apt-get update &&  apt-get build-dep python3.5 -y --allow-change-held-packages
RUN curl -sL https://deb.nodesource.com/setup_12.x | bash - && \
    apt-get install --allow-change-held-packages -y nodejs

ADD https://packages.wazuh.com/utils/gcc/gcc_14.3-1_arm64.deb /tmp/gcc_14.3-1_arm64.deb
RUN dpkg -i /tmp/gcc_14.3-1_arm64.deb && \
    ln -fs /opt/gcc-14/bin/g++ /usr/bin/c++ && \
    ln -fs /opt/gcc-14/bin/g++ /usr/bin/g++ && \
    ln -fs /opt/gcc-14/bin/gcc /usr/bin/gcc

ENV CPLUS_INCLUDE_PATH "/opt/gcc-14/include/c++/14.3.0/"
ENV LD_LIBRARY_PATH "/opt/gcc-14/lib64:${LD_LIBRARY_PATH}"
ENV PATH "/opt/gcc-14/bin:${PATH}"

ADD https://packages.wazuh.com/utils/binutils/binutils_2.38-1_arm64.deb /tmp/binutils_2.38-1_arm64.deb
RUN dpkg -i /tmp/binutils_2.38-1_arm64.deb

ENV PATH "/opt/binutils-2/bin:${PATH}"

ADD https://github.com/Kitware/CMake/releases/download/v3.30.4/cmake-3.30.4-linux-aarch64.sh /tmp/cmake-3.30.4-linux-aarch64.sh

RUN mkdir -p /opt/cmake
RUN sh /tmp/cmake-3.30.4-linux-aarch64.sh --prefix=/opt/cmake --skip-license

RUN ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake
RUN ln -s /opt/cmake/bin/ctest /usr/local/bin/ctest

# Add the script to build the Debian package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package
ADD helper_function.sh /usr/local/bin/helper_function.sh
ADD gen_permissions.sh /tmp/gen_permissions.sh

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
