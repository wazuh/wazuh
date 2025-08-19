FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install supervisor wget python3 git gnupg2 gcc g++ make vim libc6-dev curl \
    policycoreutils automake autoconf libtool apt-transport-https lsb-release python3-cryptography sqlite3 cmake -y
