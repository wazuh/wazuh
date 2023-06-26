FROM ubuntu:20.04
LABEL Description="Build indexer environment"

ENV HOME /root
ENV DEBIAN_FRONTEND noninteractive

SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get -y --no-install-recommends install \
      build-essential \
      clang \
      gdb \
      wget

RUN apt-get update && apt-get -y --no-install-recommends install \
      curl \
      python \
      python3-pip \
      gcc \
      g++ \
      make \
      libc6-dev \
      policycoreutils \
      automake \
      autoconf \
      libtool \
      libssl-dev \
      ca-certificates


RUN apt-get update && apt-get -y --no-install-recommends install \
      debconf \
      adduser \
      procps \
      gnupg \
      apt-transport-https \
      systemd \
      gawk \
      lsof

RUN pip3 install \
      boto3==1.17.85 \
      botocore==1.20.85 \
      jmespath==0.9.5 \
      python-dateutil==2.8.1 \
      six==1.14.0 \
      urllib3==1.26.5 \
      s3transfer==0.4.2 \
      pyarrow==8.0.0 \
      numpy==1.21.6

RUN apt-get update && apt-get -y --no-install-recommends install \
      vim \
      iputils-ping \
      net-tools \
      ssh

RUN curl -OL https://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz && \
        tar -zxf cmake-3.18.3.tar.gz && cd cmake-3.18.3 && \
        ./bootstrap --no-system-curl && make -j$(nproc) && \
        make install && \
        cd .. && rm -rf cmake-*

RUN apt-get update && apt-get -y --no-install-recommends install \
	git \
      gcc-mingw-w64 \
      nsis \ 
      lcov \
      zip

WORKDIR /root

RUN curl -Ls https://github.com/wazuh/wazuh/archive/v4.4.4.tar.gz | tar zx
RUN cd wazuh-4.4.4 && make TARGET=agent DEBUG=1 TEST=1 -C src deps


RUN curl -OL https://git.cryptomilk.org/projects/cmocka.git/snapshot/cmocka-1.1.7.tar.gz && \
        tar -zxf cmocka-1.1.7.tar.gz && cd cmocka-1.1.7  && \
        sed -i "/BUILD_SHARED_LIBS/ s/ON/OFF/" DefineOptions.cmake && \
        mkdir build && cd build && \
        cmake -DCMAKE_BUILD_TYPE=Release .. && \
        # For windows
        #cmake -DCMAKE_C_COMPILER=i686-w64-mingw32-gcc -DCMAKE_C_LINK_EXECUTABLE=i686-w64-mingw32-ld -DCMAKE_INSTALL_PREFIX=/usr/i686-w64-mingw32/ -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_BUILD_TYPE=Release ..
        make && \
        make install

RUN cd wazuh-4.4.4 && make TARGET=agent DEBUG=1 TEST=1 -C src
RUN cd wazuh-4.4.4/src/unit_tests && mkdir build && \
            cd build && \
            cmake -DTARGET=agent .. && \
            make

# ```

# If you need to build cmocka for the Linux targets, keep `BUILD_SHARED_LIBS` as `ON` and run the following commands
# ```
# mkdir build
# cd build
# cmake -DCMAKE_BUILD_TYPE=Release ..
# make
# sudo make install
# ```




