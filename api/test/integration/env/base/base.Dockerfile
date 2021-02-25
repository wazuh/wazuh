FROM ubuntu:18.04

RUN apt-get update && apt-get install supervisor wget python python3 git gnupg2 gcc g++ make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python-cryptography sqlite3 -y && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/staging/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh.list

# Install cmake version 3.12.4
RUN wget http://www.cmake.org/files/v3.12/cmake-3.12.4.tar.gz
RUN tar xf cmake-3.12.4.tar.gz
RUN cd cmake-3.12.4 && ./configure && make install
