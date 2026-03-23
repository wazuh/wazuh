FROM arm64v8/centos:7

ARG BINUTILS_MAJOR_VERSION=2
ARG BINUTILS_MINOR_VERSION=39

# CentOS 7 is EOL, so we need to change the repositories to use the vault
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

# Enable EPEL
RUN yum install -y http://packages.wazuh.com/utils/pkg/epel-release-latest-7.noarch.rpm

RUN yum -y install git make bzip2 xz wget \
                   texinfo flex diffutils which ruby rubygems gcc bison g++ && \
    yum clean all

WORKDIR /usr/src
RUN wget https://ftp.gnu.org/gnu/binutils/binutils-${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION}.tar.gz \
 && tar -xf binutils-${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION}.tar.gz \
 && cd binutils-${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION} \
 && mkdir build && cd build \
 && ../configure \
        --prefix=/opt/binutils-${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION} \
        --disable-gprofng \
 && make -j$(nproc) \
 && make install-strip

RUN yum -y install rpm-build
RUN mkdir -p /packages && \
    mkdir -p /tmp/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS} && \
    mkdir -p /tmp/rpmbuild/SOURCES/binutils${BINUTILS_MAJOR_VERSION}/opt && \
    cp -a /opt/binutils-${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION} /tmp/rpmbuild/SOURCES/binutils${BINUTILS_MAJOR_VERSION}/opt/binutils-${BINUTILS_MAJOR_VERSION} && \
    printf "Name: binutils${BINUTILS_MAJOR_VERSION}\n\
Version: ${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION}\n\
Release: 1\n\
Summary: GNU Binary Utilities ${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION} built manually\n\
License: GPLv3+\n\
Group: Development/Tools\n\
BuildArch: aarch64\n\
AutoReqProv: no\n\
%%description\n\
GNU binutils ${BINUTILS_MAJOR_VERSION}.${BINUTILS_MINOR_VERSION} built manually and installed to /opt/binutils-${BINUTILS_MAJOR_VERSION}.\n\
%%install\n\
mkdir -p %%{buildroot}/opt\n\
cp -a %%{_sourcedir}/binutils${BINUTILS_MAJOR_VERSION}/opt/binutils-${BINUTILS_MAJOR_VERSION} %%{buildroot}/opt/\n\
%%files\n\
/opt/binutils-${BINUTILS_MAJOR_VERSION}\n" > /tmp/rpmbuild/SPECS/binutils${BINUTILS_MAJOR_VERSION}.spec && \
    rpmbuild -bb --define "_topdir /tmp/rpmbuild" /tmp/rpmbuild/SPECS/binutils${BINUTILS_MAJOR_VERSION}.spec && \
    cp /tmp/rpmbuild/RPMS/aarch64/*.rpm /packages && \
    rm -rf /tmp/rpmbuild