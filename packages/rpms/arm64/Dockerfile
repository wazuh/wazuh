FROM registry.access.redhat.com/ubi8/ubi:8.10

ADD https://public-yum.oracle.com/RPM-GPG-KEY-oracle-ol8 /RPM-GPG-KEY-oracle-ol8
RUN rpm --import RPM-GPG-KEY-oracle-ol8 && \
    rpm -i https://public-yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/aarch64/getPackage/oraclelinux-release-el8-1.0-38.el8.aarch64.rpm && \
    rpm -i https://public-yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/aarch64/getPackage/oraclelinux-developer-release-el8-1.0-7.el8.aarch64.rpm

RUN yum install -y \
    gcc-toolset-11 \
    kernel-devel \
    perl-IPC-Cmd \
    perl-Data-Dumper \
    autoconf \
    perl \
    bzip2 \
    bzip2-devel \
    nss-devel \
    popt-devel \
    automake \
    libtool \
    wget \
    sudo \
    gettext \
    curl-devel \
    xz \
    elfutils \
    scl-utils \
    zlib-devel \
    epel-release \
    git \
    libarchive \
    file \
    policycoreutils-python-utils

RUN yum install zlib lzip libdb-devel -y && \
    rpm -i https://public-yum.oracle.com/repo/OracleLinux/OL8/codeready/builder/aarch64/getPackage/file-devel-5.33-26.el8.aarch64.rpm  && \
    rpm -i https://public-yum.oracle.com/repo/OracleLinux/OL8/codeready/builder/aarch64/getPackage/libarchive-devel-3.3.3-5.el8.aarch64.rpm

RUN scl enable gcc-toolset-11 bash

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

ADD https://github.com/Kitware/CMake/releases/download/v3.30.4/cmake-3.30.4-linux-aarch64.sh /tmp/cmake-3.30.4-linux-aarch64.sh

RUN mkdir -p /opt/cmake
RUN sh /tmp/cmake-3.30.4-linux-aarch64.sh --prefix=/opt/cmake --skip-license

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
RUN scl enable gcc-toolset-11 "cd /build_deps_vcpkg && vcpkg install --triplet arm64-linux --feature-flags=manifests"

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package
ADD helper_function.sh /usr/local/bin/helper_function.sh


# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
