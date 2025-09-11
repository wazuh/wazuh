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
# CMake 3.22
# -------------------------------------------------------------------
RUN curl -LO https://github.com/Kitware/CMake/releases/download/v3.22.0/cmake-3.22.0-linux-aarch64.sh && \
    bash cmake-3.22.0-linux-aarch64.sh --skip-license --prefix=/usr/local && \
    rm -f cmake-3.22.0-linux-aarch64.sh

# -------------------------------------------------------------------
# GCC 14.3.0
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
    rm -rf /usr/local/gcc-9.4.0   # limpiar bootstrap si no lo necesitas más

# -------------------------------------------------------------------
# GCC 14.3 ENV vars
# -------------------------------------------------------------------
ENV PATH="/usr/local/gcc-14.3.0/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/gcc-14.3.0/lib64"
ENV CC="/usr/local/gcc-14.3.0/bin/gcc"
ENV CXX="/usr/local/gcc-14.3.0/bin/g++"

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
