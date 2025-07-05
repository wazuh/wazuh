FROM arm64v8/centos:7

# CentOS 7 is EOL, so we need to change the repositories to use the vault
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

# Enable EPEL
RUN yum install -y http://packages.wazuh.com/utils/pkg/epel-release-latest-7.noarch.rpm

# Install all the necessary tools to build the packages
RUN yum install -y gcc make wget git \
    openssh-clients sudo gnupg file-devel\
    automake autoconf libtool policycoreutils-python \
    yum-utils system-rpm-config rpm-devel \
    gettext nspr nspr-devel \
    nss nss-devel libdb libdb-devel \
    zlib zlib-devel rpm-build bison \
    sharutils bzip2-devel xz-devel lzo-devel \
    e2fsprogs-devel libacl-devel libattr-devel \
    openssl-devel libxml2-devel kexec-tools elfutils \
    libcurl-devel elfutils-libelf-devel \
    elfutils-libelf patchelf elfutils-devel libgcrypt-devel \
    libarchive-devel libarchive bluez-libs-devel bzip2 \
    desktop-file-utils expat-devel findutils gcc-c++ gdbm-devel \
    glibc-devel gmp-devel gnupg2 libappstream-glib \
    libffi-devel libtirpc-devel libGL-devel libuuid-devel \
    libX11-devel ncurses-devel pkgconfig readline-devel \
    redhat-rpm-config sqlite-devel gdb tar tcl-devel tix-devel tk-devel \
    valgrind-devel python-rpm-macros python34 nodejs

ADD https://packages.wazuh.com/utils/gcc/gcc-14.3-1.aarch64.rpm /tmp/gcc-14.3-1.aarch64.rpm
RUN rpm -i /tmp/gcc-14.3-1.aarch64.rpm && \
    ln -fs /opt/gcc-14/bin/g++ /usr/bin/c++ && \
    ln -fs /opt/gcc-14/bin/g++ /usr/bin/g++ && \
    ln -fs /opt/gcc-14/bin/gcc /usr/bin/gcc

ENV CPLUS_INCLUDE_PATH "/opt/gcc-14/include/c++/14.3.0/"
ENV LD_LIBRARY_PATH "/opt/gcc-14/lib64:${LD_LIBRARY_PATH}"
ENV PATH "/opt/gcc-14/bin:${PATH}"

ADD https://packages.wazuh.com/utils/binutils/binutils-2.38-1.aarch64.rpm /tmp/binutils-2.38-1.aarch64.rpm
RUN rpm -i /tmp/binutils-2.38-1.aarch64.rpm

ENV PATH "/opt/binutils-2/bin:${PATH}"

ADD https://github.com/Kitware/CMake/releases/download/v3.30.4/cmake-3.30.4-linux-aarch64.sh /tmp/cmake-3.30.4-linux-aarch64.sh

RUN mkdir -p /opt/cmake
RUN sh /tmp/cmake-3.30.4-linux-aarch64.sh --prefix=/opt/cmake --skip-license

RUN ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake
RUN ln -s /opt/cmake/bin/ctest /usr/local/bin/ctest

# Install Perl 5.10
RUN curl -OL http://packages.wazuh.com/utils/perl/perl-5.10.1.tar.gz && \
    gunzip perl-5.10.1.tar.gz && tar -xf perl*.tar && \
    cd /perl-5.10.1 && ./Configure -des -Dcc='gcc' -Dusethreads && \
    make -j2 && make install && ln -fs /usr/local/bin/perl /bin/perl && \
    cd / && rm -rf /perl-5.10.1*

RUN curl -O http://packages.wazuh.com/utils/openssl/openssl-1.1.1a.tar.gz && \
    tar -xzf openssl-1.1.1a.tar.gz && cd openssl* && \
    ./config -Wl,--enable-new-dtags,-rpath,'$(LIBRPATH)' && \
    make -j $(nproc) && make install && cd / && rm -rf openssl-*

RUN curl -O http://packages.wazuh.com/utils/nodejs/node-v12.16.1-linux-arm64.tar.xz && \
    tar -xJf node-v12.16.1-linux-arm64.tar.xz && \
    cd node-v12.16* && cp -R * /usr/local/ && cd / && rm -rf node-v*

# Update rpmbuild, rpm and autoconf
RUN curl -O http://packages.wazuh.com/utils/autoconf/autoconf-2.69.tar.gz && \
    gunzip autoconf-2.69.tar.gz && tar xvf autoconf-2.69.tar && \
    cd autoconf-2.69 && ./configure && \
    make -j $(nproc) && make install && cd / && rm -rf autoconf-*

RUN curl -O http://packages.wazuh.com/utils/rpm/rpm-4.15.1.tar.bz2 && \
    tar -xjf rpm-4.15.1.tar.bz2 && cd rpm-4.15.1 && \
    ./configure --without-lua && make -j $(nproc) && \
    make install && cd / && rm -rf rpm-*

RUN mkdir -p /usr/local/var/lib/rpm && \
    cp /var/lib/rpm/Packages /usr/local/var/lib/rpm/Packages && \
    /usr/local/bin/rpm --rebuilddb && rm -rf /root/rpmbuild

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package
ADD helper_function.sh /usr/local/bin/helper_function.sh

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
