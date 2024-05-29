FROM arm64v8/centos:7

# Enable EPEL
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

# Install all the necessary tools to build the packages
RUN yum install -y gcc make git sudo gnupg openssl \
    automake autoconf libtool policycoreutils-python \
    findutils gcc-c++ glibc-devel gnupg2 openssl openssl-devel \
    libffi-devel pkgconfig readline-devel \
    sqlite-devel gdb tar tcl-devel tix-devel tk-devel \
    valgrind-devel python-rpm-macros python36 python36-devel jq

RUN curl https://bootstrap.pypa.io/get-pip.py | python3 -

RUN pip3 install --upgrade cryptography awscli

ADD wpkpack.py /usr/local/bin/wpkpack
ADD run.sh /usr/local/bin/run
ENTRYPOINT ["/usr/local/bin/run"]
