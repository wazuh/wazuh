FROM redhat/ubi9:9.5

RUN yum update -y && yum install -y \
    pip \
    procps \
    && yum clean all

RUN pip3 install cryptography
