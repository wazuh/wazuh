FROM ubuntu:22.04

# Installing necessary packages
RUN apt-get update && \
    apt-get install -y --allow-change-held-packages gcc g++ gcc-mingw-w64 g++-mingw-w64 nsis make wget unzip \
    curl perl binutils zip libssl-dev git && \
    rm -rf /var/lib/apt/lists/*

RUN curl -OL http://packages.wazuh.com/utils/cmake/cmake-3.18.3.tar.gz && \
    tar -zxvf cmake-3.18.3.tar.gz && \
    cd cmake-3.18.3 && \
    ./bootstrap && make -j$(nproc) && make install && \
    ln -s /usr/local/bin/cmake /usr/bin/cmake && cd / && rm -rf cmake-*

# Install wine from source
RUN git clone https://gitlab.winehq.org/wine/wine.git -b wine-9.20 --depth 1 
RUN apt-get update && \
    apt-get install -y bison flex gcc-multilib g++-multilib && \
    rm -rf /var/lib/apt/lists/*
RUN cd wine && ./configure --without-x --without-freetype && make && make install && \
    cd / && rm -rf wine*

ADD entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
