FROM ubuntu:22.04

RUN apt update && apt install -y \
    curl \
    lsb-release \
    pip \
    procps \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install cryptography
