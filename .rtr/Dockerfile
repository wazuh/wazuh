FROM ubuntu:jammy

RUN apt-get update
RUN apt-get install -y gcc g++ clang-format cmake python3 clang-tools wget curl lcov valgrind acl
RUN wget https://github.com/danmar/cppcheck/archive/refs/tags/2.8.tar.gz && \
    tar xfz 2.8.tar.gz && \
    cmake -S cppcheck-2.8/ -B cppcheck-2.8/build && \
    cmake --build cppcheck-2.8/build -j && \
    cmake --install cppcheck-2.8/build
