FROM ubuntu:22.04

ARG WAZUH_BRANCH
ENV DEBIAN_FRONTEND="noninteractive"

RUN apt update && \
    apt install -y wget python3 python3-pip git gnupg2 gcc g++ cmake make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python3-cryptography sqlite3

RUN mkdir wazuh && curl -sL https://github.com/wazuh/wazuh/tarball/${WAZUH_BRANCH} | tar zx --strip-components=1 -C wazuh
RUN make -C /wazuh/src deps
