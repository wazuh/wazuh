FROM arm64v8/centos:7

ARG GCC_MAJOR_VERSION=14
ARG GCC_MINOR_VERSION=3

# CentOS 7 is EOL, so we need to change the repositories to use the vault
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

# Enable EPEL
RUN yum install -y http://packages.wazuh.com/utils/pkg/epel-release-latest-7.noarch.rpm

RUN yum -y install gcc gcc-c++ \
                   git make bzip2 xz wget \
                   gmp-devel mpfr-devel libmpc-devel isl-devel zlib-devel \
                   texinfo flex diffutils which ruby rubygems && \
    yum clean all

WORKDIR /usr/src

ARG GCC_STAGE1_VER=8.5.0
RUN curl -LO https://ftp.gnu.org/gnu/gcc/gcc-${GCC_STAGE1_VER}/gcc-${GCC_STAGE1_VER}.tar.xz && \
    tar -xf gcc-${GCC_STAGE1_VER}.tar.xz && \
    cd gcc-${GCC_STAGE1_VER} && \
    ./contrib/download_prerequisites && \
    mkdir build && cd build && \
    ../configure --prefix=/opt/gcc-${GCC_STAGE1_VER} \
                    --disable-multilib \
                    --enable-languages=c,c++ \
                    --with-system-zlib \
                    --disable-bootstrap && \
    make -j2 && make install-strip

ENV PATH=/opt/gcc-8.5.0/bin:$PATH \
    CC=/opt/gcc-8.5.0/bin/gcc \
    CXX=/opt/gcc-8.5.0/bin/g++
    
    
RUN wget https://ftp.gnu.org/gnu/gcc/gcc-${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION}.0/gcc-${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION}.0.tar.xz \
 && tar -xf gcc-${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION}.0.tar.xz \
 && cd gcc-${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION}.0 \
 && ./contrib/download_prerequisites \
 && mkdir build && cd build \
 && ../configure \
        --prefix=/opt/gcc-${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION} \
        --disable-multilib \
        --enable-default-dwarf=2 \
        --enable-languages=c,c++ \
        --with-system-zlib \
 && make -j2 \
 && make install-strip

RUN yum -y install rpm-build
RUN mkdir -p /packages && \
    mkdir -p /tmp/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS} && \
    mkdir -p /tmp/rpmbuild/SOURCES/gcc${GCC_MAJOR_VERSION}/opt && \
    cp -a /opt/gcc-${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION} /tmp/rpmbuild/SOURCES/gcc${GCC_MAJOR_VERSION}/opt/gcc-${GCC_MAJOR_VERSION} && \
    printf "Name: gcc${GCC_MAJOR_VERSION}\n\
Version: ${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION}\n\
Release: 1\n\
Summary: GNU Compiler Collection ${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION} built manually\n\
License: GPLv3+\n\
Group: Development/Tools\n\
BuildArch: aarch64\n\
AutoReqProv: no\n\
%%description\n\
GCC ${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION} built manually and installed to /opt/gcc-${GCC_MAJOR_VERSION}.\n\
%%install\n\
mkdir -p %%{buildroot}/opt\n\
cp -a %%{_sourcedir}/gcc${GCC_MAJOR_VERSION}/opt/gcc-${GCC_MAJOR_VERSION} %%{buildroot}/opt/\n\
%%files\n\
/opt/gcc-${GCC_MAJOR_VERSION}\n" > /tmp/rpmbuild/SPECS/gcc${GCC_MAJOR_VERSION}.spec && \
    rpmbuild -bb --define "_topdir /tmp/rpmbuild" /tmp/rpmbuild/SPECS/gcc${GCC_MAJOR_VERSION}.spec && \
    cp /tmp/rpmbuild/RPMS/aarch64/*.rpm /packages && \
    rm -rf /tmp/rpmbuild
