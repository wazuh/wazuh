FROM centos:6

# Install all the necessary tools to build the packages
RUN rm /etc/yum.repos.d/* && echo "exactarch=1" >> /etc/yum.conf
COPY CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo
RUN yum clean all && yum update -y
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6
RUN yum install -y gcc make wget git \
    openssh-clients sudo gnupg \
    automake autoconf libtool policycoreutils-python \
    yum-utils epel-release redhat-rpm-config rpm-devel \
    autopoint gettext nspr nspr-devel \
    nss nss-devel kenel-headers magic magic-devel \
    db4 db4-devel zlib zlib-devel rpm-build bison \
    sharutils bzip2-devel xz-devel lzo-devel \
    e2fsprogs-devel libacl-devel libattr-devel \
    openssl-devel libxml2-devel kexec-tools elfutils \
    libarchive-devel elfutils-libelf-devel \
    elfutils-libelf patchelf elfutils-devel libgcrypt-devel

RUN yum-builddep python34 -y

RUN curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
RUN yum install -y nodejs

# Update rpmbuild, rpm and autoconf
RUN curl -O http://packages.wazuh.com/utils/autoconf/autoconf-2.69.tar.gz && \
    gunzip autoconf-2.69.tar.gz && tar xvf autoconf-2.69.tar && \
    cd autoconf-2.69 && ./configure && make -j$(nproc) && \
    make install && cd / && rm -rf autoconf-*

RUN curl -O https://packages.wazuh.com/utils/libarchive/libarchive-3.1.2-12.el7.src.rpm && \
    rpmbuild --rebuild libarchive-3.1.2-12.el7.src.rpm && rpm -Uvh /root/rpmbuild/RPMS/x86_64/* --nodeps && rm -rf libarchive-*

RUN curl -O http://packages.wazuh.com/utils/rpm/rpm-4.15.1.tar.bz2 && \
    tar -xjf rpm-4.15.1.tar.bz2 && cd rpm-4.15.1 && \
    ./configure --without-lua && make -j$(nproc) && make install && cd / && rm -rf rpm-*

RUN mkdir -p /usr/local/var/lib/rpm && \
    cp /var/lib/rpm/Packages /usr/local/var/lib/rpm/Packages && \
    /usr/local/bin/rpm --rebuilddb && rm -rf /root/rpmbuild

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
# Binutils
# -------------------------------------------------------------------
RUN yum install -y flex && \
    curl -OL https://github.com/bminor/binutils-gdb/archive/refs/tags/binutils-2_41.zip && \
    unzip binutils-2_41.zip && rm -f binutils-2_41.zip && \
    cd binutils-gdb-binutils-2_41 && mkdir build && cd build && \
    ../configure --disable-gdb --disable-werror --disable-zlib \
        --disable-gprofng --disable-gdbserver --disable-gdbsupport \
        --disable-gnulib --disable-gold --disable-gprof --disable-texinfo \
        --disable-binutils --disable-sim && \
    make MAKEINFO=true -j$(nproc) && make MAKEINFO=true install && \
    cd / && rm -rf binutils-gdb-binutils-2_41 && \
    ln -fs /usr/local/bin/ld /usr/bin/ld

# -------------------------------------------------------------------
# CMake 3.22
# -------------------------------------------------------------------
RUN curl -LO https://github.com/Kitware/CMake/releases/download/v3.22.0/cmake-3.22.0-Linux-x86_64.sh && \
    bash cmake-3.22.0-Linux-x86_64.sh --skip-license --prefix=/usr/local && \
    rm -f cmake-3.22.0-Linux-x86_64.sh

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

# -------------------------------------------------------------------
# Set entrypoint
# -------------------------------------------------------------------
ENTRYPOINT ["/usr/local/bin/build_package"]
