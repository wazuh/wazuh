FROM centos:7

RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

ADD https://public-yum.oracle.com/RPM-GPG-KEY-oracle-ol7 /RPM-GPG-KEY-oracle-ol7
RUN rpm --import RPM-GPG-KEY-oracle-ol7 && \
    rpm -i https://yum.oracle.com/repo/OracleLinux/OL7/latest/x86_64/getPackage/oraclelinux-release-el7-1.0-17.el7.x86_64.rpm && \
    rpm -i https://yum.oracle.com/repo/OracleLinux/OL7/latest/x86_64/getPackage/oracle-softwarecollection-release-el7-1.0-4.el7.x86_64.rpm

RUN yum install -y \
    devtoolset-11 \
    kernel-devel \
    perl-IPC-Cmd \
    perl-Data-Dumper \
    epel-release \
    autoconf \
    perl \
    lzip \
    bzip2 \
    make \
    nss-devel \
    file-devel \
    popt-devel \
    libarchive-devel \
    automake \
    libtool \
    wget \
    sudo \
    gettext \
    curl-devel \
    xz \
    elfutils

RUN yum install epel-release -y
RUN yum install lzip -y

RUN scl enable devtoolset-11 bash

ADD https://github.com/git/git/archive/refs/tags/v2.18.0.tar.gz /tmp/git-2.18.0.tar.gz
WORKDIR /tmp
RUN tar -xzf git-2.18.0.tar.gz
WORKDIR /tmp/git-2.18.0
RUN make configure
RUN ./configure --prefix=/usr
RUN CFLAGS='-std=c99' make -j$(nproc)
RUN make install
WORKDIR /
RUN rm -rf /tmp/git-2.18.0

ADD http://packages.wazuh.com/utils/rpm/rpm-4.15.1.tar.bz2 /tmp/rpm-4.15.1.tar.bz2
WORKDIR /tmp
RUN tar -xjf rpm-4.15.1.tar.bz2
WORKDIR /tmp/rpm-4.15.1
RUN ./configure --without-lua && make -j$(nproc) && make install
WORKDIR /
RUN rm -rf /tmp/rpm-4.15.1

RUN mkdir -p /usr/local/var/lib/rpm && \
    cp /var/lib/rpm/Packages /usr/local/var/lib/rpm/Packages && \
    /usr/local/bin/rpm --rebuilddb && rm -rf /root/rpmbuild

ADD https://github.com/Kitware/CMake/releases/download/v3.30.4/cmake-3.30.4-linux-x86_64.sh /tmp/cmake-3.30.4-linux-x86_64.sh

RUN mkdir -p /opt/cmake
RUN sh /tmp/cmake-3.30.4-linux-x86_64.sh --prefix=/opt/cmake --skip-license

RUN ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake
RUN ln -s /opt/cmake/bin/ctest /usr/local/bin/ctest

# Install vcpkg
ENV VCPKG_ROOT=/root/vcpkg
RUN git clone "https://github.com/microsoft/vcpkg.git" "$VCPKG_ROOT" \
    && cd "$VCPKG_ROOT" \
    && ./bootstrap-vcpkg.sh \
    && echo "export VCPKG_ROOT=$VCPKG_ROOT" >> ~/.bashrc \
    && echo "export PATH=$PATH:$VCPKG_ROOT" >> ~/.bashrc

# Install vcpkg packages using vcpkg json file
COPY vcpkg.json /build_deps_vcpkg/vcpkg.json
COPY vcpkg-configuration.json /build_deps_vcpkg/vcpkg-configuration.json
ENV PATH=$PATH:$VCPKG_ROOT
RUN scl enable devtoolset-11 "cd /build_deps_vcpkg && vcpkg install --triplet x64-linux --feature-flags=manifests"

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package
ADD helper_function.sh /usr/local/bin/helper_function.sh


# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
