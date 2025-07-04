FROM centos:7

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
RUN wget https://ftp.gnu.org/gnu/gcc/gcc-15.1.0/gcc-15.1.0.tar.xz \
 && tar -xf gcc-15.1.0.tar.xz \
 && cd gcc-15.1.0 \
 && ./contrib/download_prerequisites \
 && mkdir build && cd build \
 && ../configure \
        --prefix=/opt/gcc-15.1 \
        --disable-multilib \
        --enable-languages=c,c++ \
        --with-system-zlib \
 && make -j6 \
 && make install-strip

RUN yum -y install rpm-build
RUN mkdir -p /packages && \
    mkdir -p /tmp/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS} && \
    mkdir -p /tmp/rpmbuild/SOURCES/gcc15/opt && \
    cp -a /opt/gcc-15.1 /tmp/rpmbuild/SOURCES/gcc15/opt/gcc-15 && \
    printf "Name: gcc15\n\
Version: 15.1\n\
Release: 1\n\
Summary: GNU Compiler Collection 15.1 built manually\n\
License: GPLv3+\n\
Group: Development/Tools\n\
BuildArch: x86_64\n\
AutoReqProv: no\n\
%%description\n\
GCC 15.1 built manually and installed to /opt/gcc-15.\n\
%%install\n\
mkdir -p %%{buildroot}/opt\n\
cp -a %%{_sourcedir}/gcc15/opt/gcc-15 %%{buildroot}/opt/\n\
%%files\n\
/opt/gcc-15\n" > /tmp/rpmbuild/SPECS/gcc15.spec && \
    rpmbuild -bb --define "_topdir /tmp/rpmbuild" /tmp/rpmbuild/SPECS/gcc15.spec && \
    cp /tmp/rpmbuild/RPMS/x86_64/*.rpm /packages && \
    rm -rf /tmp/rpmbuild
