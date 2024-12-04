# Ubutnu 24.04
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
	&& localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8

ENV LANG=en_US.utf8
ENV REINSTALL_CMAKE_VERSION_FROM_SOURCE="3.30.5"

# Engine specific environment variables
ENV WAZUH_ROOT=/root/wazuh
ENV ENGINE_SRC=$WAZUH_ROOT/src/engine
ENV ENGINE_BUILD=$ENGINE_SRC/build

# Force use the specific commit of master to aviod breaking changes like:
# - Python packages
# - Engine configuration and CLI
ENV ENGINE_COMMIT_ID=3fd4d415a8e7a185a5e1f58b5197ed0fd0c112d2
ENV ENGINE_PRESET=release
ENV ENGINE_ON_BACKGROUND=1
ENV MM_LICENCE_KEY=

# Install dependencies
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/New_York
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    clang-format \
    cmake \
    git \
    openssh-server \
    python3 \
    python3-pip \
    curl \
    zip \
    lzip \
    unzip \
    tar
ENV DEBIAN_FRONTEND=dialog

# Install vcpkg
ENV VCPKG_ROOT=/root/vcpkg
RUN git clone "https://github.com/microsoft/vcpkg.git" $VCPKG_ROOT \
    && cd $VCPKG_ROOT \
    && ./bootstrap-vcpkg.sh \
    && echo "export VCPKG_ROOT=$VCPKG_ROOT" >> ~/.bashrc \
    && echo "export PATH=\$PATH:\$VCPKG_ROOT" >> ~/.bashrc

# Install CMake
COPY scripts/reinstall-cmake.sh /tmp/reinstall-cmake.sh
RUN chmod +x /tmp/reinstall-cmake.sh && /tmp/reinstall-cmake.sh ${REINSTALL_CMAKE_VERSION_FROM_SOURCE}

# Build, install engine and tools
COPY mmdbs/GeoLite2-City.mmdb /tmp/GeoLite2-City.mmdb
COPY mmdbs/GeoLite2-ASN.mmdb /tmp/GeoLite2-ASN.mmdb
COPY scripts/build-and-install-engine.sh /tmp/build-and-install-engine.sh
RUN chmod +x /tmp/build-and-install-engine.sh && /tmp/build-and-install-engine.sh


# Configure SSH server (https://www.cherryservers.com/blog/ssh-into-docker-container)
RUN mkdir /var/run/sshd
# Set root password for SSH access (change 'Engine123' to your desired password)
RUN echo 'root:Engine123' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PermitRootLogin yes/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
EXPOSE 22

# Install Github CLI
RUN mkdir -p -m 755 /etc/apt/keyrings \
    && wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt update \
    && apt install gh -y


# Start SSH server and wazuh-engine
COPY scripts/EntryPoint.sh /usr/bin/EntryPoint.sh
RUN chmod +x /usr/bin/EntryPoint.sh
CMD ["/usr/bin/EntryPoint.sh"]
