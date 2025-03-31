FROM arm64v8/ubuntu:jammy

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update -y && \
    apt install -y checkpolicy curl devscripts equivs g++ gawk gcc git libaudit-dev libauparse0 \
    libblas3 libcap-ng-dev libgfortran5 liblapack3 libssl-dev make pkg-config policycoreutils policycoreutils-dev \
    policycoreutils-python-utils python3 python3-audit python3-decorator python3-networkx \
    python3-numpy python3-selinux python3-semanage python3-sepolgen python3-sepolicy \
    python3-setools python3-yaml selinux-basics selinux-policy-default selinux-policy-dev \
    selinux-utils semodule-utils setools sudo tar unzip wget zip && \
    rm -rf /var/lib/apt/lists/*

ADD https://github.com/Kitware/CMake/releases/download/v3.30.4/cmake-3.30.4-linux-aarch64.sh /tmp/cmake-3.30.4-linux-aarch64.sh

RUN mkdir -p /opt/cmake
RUN sh /tmp/cmake-3.30.4-linux-aarch64.sh --prefix=/opt/cmake --skip-license

RUN ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake
RUN ln -s /opt/cmake/bin/ctest /usr/local/bin/ctest

# Install vcpkg
ENV VCPKG_ROOT=/root/vcpkg
RUN git clone "https://github.com/microsoft/vcpkg.git" "$VCPKG_ROOT" \
    && cd "$VCPKG_ROOT" \
    && ./bootstrap-vcpkg.sh \
    && echo "export VCPKG_ROOT=$VCPKG_ROOT" >> ~/.bashrc \
    && echo "export PATH=\$PATH:\$VCPKG_ROOT" >> ~/.bashrc

# Install vcpkg packages using vcpkg json file
COPY vcpkg.json /build_deps_vcpkg/vcpkg.json
COPY vcpkg-configuration.json /build_deps_vcpkg/vcpkg-configuration.json
ENV PATH=$PATH:$VCPKG_ROOT
RUN cd /build_deps_vcpkg && vcpkg install --triplet x64-linux --feature-flags=manifests

# Add the script to build the Debian package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package
ADD helper_function.sh /usr/local/bin/helper_function.sh
ADD gen_permissions.sh /tmp/gen_permissions.sh

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
