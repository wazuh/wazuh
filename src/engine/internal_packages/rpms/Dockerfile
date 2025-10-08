FROM rockylinux:8

ENV TERM=xterm-256color \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8

RUN dnf -y update && \
    dnf -y groupinstall "Development Tools" && \
    dnf -y install \
      rpm-build rpmdevtools redhat-rpm-config \
      dnf-plugins-core \
      python38 python38-pip python38-setuptools python38-wheel \
      git which findutils sed tar gzip rsync \
      ca-certificates && \
    dnf -y config-manager --set-enabled powertools || true && \
    dnf clean all && rm -rf /var/cache/dnf/*

COPY build.sh /usr/local/bin/build.sh
RUN chmod +x /usr/local/bin/build.sh

ENTRYPOINT ["/usr/local/bin/build.sh"]
