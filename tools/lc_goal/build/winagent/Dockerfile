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
	git

WORKDIR /root

RUN curl -Ls https://github.com/wazuh/wazuh/archive/v4.4.4.tar.gz | tar zx
RUN cd wazuh-4.4.4 && make -C src clean && make -C src clean-deps


RUN apt-get update && apt-get -y --no-install-recommends install \
        gcc-mingw-w64 \
        g++-mingw-w64-i686 \
        g++-mingw-w64-x86-64 \
        binutils-mingw-w64-i686 \
        nsis 

RUN cd /root/wazuh-4.4.4/ && make TARGET=winagent -C src deps

RUN apt-get update && apt-get -y --no-install-recommends install \
	zip
RUN  zip -r wazuh.zip wazuh-4.4.4

RUN sed -i "s/#PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config

RUN service ssh start
