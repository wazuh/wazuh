FROM ubuntu:jammy

RUN apt-get update && apt-get install --no-install-recommends -y ca-certificates git openssl libssl-dev make gcc g++ clang-format cmake python3 clang-tools wget curl lcov valgrind acl doxygen graphviz
RUN wget https://github.com/danmar/cppcheck/archive/refs/tags/2.8.tar.gz && \
    tar xfz 2.8.tar.gz && \
    cmake -S cppcheck-2.8/ -B cppcheck-2.8/build && \
    cmake --build cppcheck-2.8/build -j$(nproc) && \
    cmake --install cppcheck-2.8/build
