FROM centos:7

ARG GCC_MAJOR_VERSION=14
ARG GCC_MINOR_VERSION=3

RUN sed -i 's|mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-*.repo && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo

RUN yum -y install centos-release-scl-rh epel-release && \
    sed -i 's|mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-SCLo-*.repo && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|g' /etc/yum.repos.d/CentOS-SCLo-*.repo

RUN yum -y install devtoolset-11-gcc devtoolset-11-gcc-c++ \
                   git make bzip2 xz wget \
                   gmp-devel mpfr-devel libmpc-devel isl-devel zlib-devel \
                   texinfo flex diffutils which ruby rubygems && \
    yum clean all

SHELL ["/bin/bash", "-c"]
RUN source /opt/rh/devtoolset-11/enable && gcc --version


ENV PATH=/opt/rh/devtoolset-11/root/usr/bin:$PATH \
    CC=gcc CXX=g++

WORKDIR /usr/src
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
BuildArch: x86_64\n\
AutoReqProv: no\n\
%%description\n\
GCC ${GCC_MAJOR_VERSION}.${GCC_MINOR_VERSION} built manually and installed to /opt/gcc-${GCC_MAJOR_VERSION}.\n\
%%install\n\
mkdir -p %%{buildroot}/opt\n\
cp -a %%{_sourcedir}/gcc${GCC_MAJOR_VERSION}/opt/gcc-${GCC_MAJOR_VERSION} %%{buildroot}/opt/\n\
%%files\n\
/opt/gcc-${GCC_MAJOR_VERSION}\n" > /tmp/rpmbuild/SPECS/gcc${GCC_MAJOR_VERSION}.spec && \
    rpmbuild -bb --define "_topdir /tmp/rpmbuild" /tmp/rpmbuild/SPECS/gcc${GCC_MAJOR_VERSION}.spec && \
    cp /tmp/rpmbuild/RPMS/x86_64/*.rpm /packages && \
    rm -rf /tmp/rpmbuild
