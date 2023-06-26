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


RUN cd /root/wazuh-4.4.4/ && make TARGET=agent -C src deps
RUN cd /root/wazuh-4.4.4/ && make TARGET=agent -C src

# Set agent instalation
RUN sed -i '330 i USER_AGENT_SERVER_IP="10.5.0.2"' wazuh-4.4.4/install.sh 
# ddRUN sed -i '330 i USER_AGENT_SERVER_NAME="src_agent_test"' wazuh-4.4.4/install.sh 
RUN sed -i '935 i USER_INSTALL_TYPE="agent"' wazuh-4.4.4/install.sh 
RUN cd wazuh-4.4.4 && ./install.sh 

