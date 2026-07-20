FROM rockylinux:8

ENV TERM=xterm-256color \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8

# 1) Plugin and powertools BEFORE installing
RUN dnf -y update && \
    dnf -y install dnf-plugins-core && \
    dnf -y config-manager --set-enabled powertools || true && \
    # 2) rpmbuild tools + python3 (generic BRs) + python38 (the one you'll use)
    dnf -y install \
      rpm-build rpmdevtools redhat-rpm-config \
      python3 python3-pip python3-setuptools python3-wheel \
      python38 python38-pip python38-setuptools python38-wheel \
      git which findutils sed tar gzip rsync ca-certificates && \
    # 3) Optional: if you are NOT compiling C, "Development Tools" is not needed
    # dnf -y groupinstall "Development Tools" && \
    dnf clean all && rm -rf /var/cache/dnf/*

# 4) Make "python3" point to 3.8 for your SPEC's %build
RUN alternatives --set python3 /usr/bin/python3.8 || true \
 && python3 -V \
 && python3 -m pip install --upgrade pip wheel setuptools

COPY build.sh /usr/local/bin/build.sh
RUN chmod +x /usr/local/bin/build.sh

ENTRYPOINT ["/usr/local/bin/build.sh"]
