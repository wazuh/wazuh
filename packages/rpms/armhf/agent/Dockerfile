FROM arm32v7/centos:7

ADD build_deps.sh /build_deps.sh
RUN sh build_deps.sh

RUN curl -OL http://packages.wazuh.com/utils/gcc/gcc-9.4.0.tar.gz && \
    tar xzf gcc-9.4.0.tar.gz  && cd gcc-9.4.0/ && \
    linux32 ./contrib/download_prerequisites && \
    linux32 ./configure --prefix=/usr/local/gcc-9.4.0 --with-arch=armv7-a \
        --with-float=hard --with-fpu=vfpv3-d16 --enable-languages=c,c++ --disable-multilib \
        --disable-libsanitizer && \
    linux32 make -j$(nproc) && linux32 make install && \
    ln -fs /usr/local/gcc-9.4.0/bin/g++ /usr/bin/c++ && \
    ln -fs /usr/local/gcc-9.4.0/bin/gcc /usr/bin/cc && cd / && rm -rf gcc-*

ENV CPLUS_INCLUDE_PATH "/usr/local/gcc-9.4.0/include/c++/9.4.0/"
ENV LD_LIBRARY_PATH "/usr/local/gcc-9.4.0/lib/"
ENV PATH "/usr/local/gcc-9.4.0/bin:${PATH}"

RUN curl -OL http://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz && \
    tar -zxf cmake-3.18.3.tar.gz && cd cmake-3.18.3 && \
    linux32 ./bootstrap --no-system-curl CC=/usr/local/gcc-9.4.0/bin/gcc \
        CXX=/usr/local/gcc-9.4.0/bin/g++ && \
    linux32 make -j$(nproc) && linux32 make install && cd / && rm -rf cmake-*

# Install Perl 5.10
RUN curl -OL http://packages.wazuh.com/utils/perl/perl-5.10.1.tar.gz && \
    gunzip perl-5.10.1.tar.gz && tar -xf perl*.tar && \
    cd /perl-5.10.1 && ./Configure -des -Dcc='gcc' -Dusethreads && \
    make -j2 && make install && ln -fs /usr/local/bin/perl /bin/perl && \
    cd / && rm -rf /perl-5.10.1*

RUN curl -O http://packages.wazuh.com/utils/openssl/openssl-1.1.1a.tar.gz && \
    tar -xzf openssl-1.1.1a.tar.gz && cd openssl* && \
    linux32 ./config -Wl,--enable-new-dtags,-rpath,'$(LIBRPATH)' && \
    linux32 make -j $(nproc) && linux32 make install && \
    make install && cd / && rm -rf openssl-*

RUN curl -O http://packages.wazuh.com/utils/nodejs/node-v4.9.1-linux-armv7l.tar.xz && \
    tar -xJf node-v4.9.1-linux-armv7l.tar.xz && cd node-v4.9.1-linux-armv7l && cp -R * /usr/local/ && cd / && rm -rf node-v*

# Update rpmbuild, rpm and autoconf
RUN curl -O http://packages.wazuh.com/utils/autoconf/autoconf-2.69.tar.gz && \
    gunzip autoconf-2.69.tar.gz && tar xvf autoconf-2.69.tar && \
    cd autoconf-2.69 && linux32 ./configure && linux32 make -j $(nproc) && \
    linux32 make install && cd / && rm -rf autoconf-*

RUN curl -O http://packages.wazuh.com/utils/rpm/rpm-4.15.1.tar.bz2 && \
    tar -xjf rpm-4.15.1.tar.bz2 && cd rpm-4.15.1 && \
    linux32 ./configure --without-lua && linux32 make -j $(nproc) && \
    linux32 make install && cd / && rm -rf rpm-*

RUN echo "%_initddir              %{_sysconfdir}/rc.d/init.d" >> /root/.rpmmacros
RUN echo "%_initrddir             %{_initddir}" >> /root/.rpmmacros
RUN echo "%_arch                  armv7hl" >> /root/.rpmmacros

RUN mkdir -p /usr/local/var/lib/rpm && \
    cp /var/lib/rpm/Packages /usr/local/var/lib/rpm/Packages && \
    /usr/local/bin/rpm --rebuilddb && rm -rf /root/rpmbuild

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package
ADD helper_function.sh /usr/local/bin/helper_function.sh

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
