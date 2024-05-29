FROM arm32v7/centos:7

ADD build_deps.sh /build_deps.sh
RUN sh build_deps.sh

RUN curl https://bootstrap.pypa.io/get-pip.py | python2.7 -
RUN pip2 install cryptography awscli


ADD wpkpack.py /usr/local/bin/wpkpack
ADD run.sh /usr/local/bin/run
ADD entrypoint.sh /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]
