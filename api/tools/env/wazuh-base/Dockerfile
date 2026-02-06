FROM ubuntu:24.04

ARG WAZUH_BRANCH
ENV DEBIAN_FRONTEND="noninteractive"

RUN apt-get update && \
    apt-get install -y git wget python3 python3-pip git gnupg2 gcc g++ cmake make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python3-cryptography sqlite3 && \
    apt-get clean

RUN git clone --depth 1 --branch "${WAZUH_BRANCH}" https://github.com/wazuh/wazuh.git /wazuh

RUN cd /wazuh/src && \
    make deps -j$(nproc) || (echo "First attempt failed, trying again.." && make deps)
