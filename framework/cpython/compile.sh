#!/bin/bash

WAZUH_ROOT_DIR=/wazuh #Important: Do not change this path
WAZUH_INSTALLDIR=/var/ossec
CPYTHON_DIR=$WAZUH_ROOT_DIR/src/external/cpython
PYTHON_VERSION=$(cat "$WAZUH_ROOT_DIR/framework/.python-version")
PIP_VERSION=$(cat "$WAZUH_ROOT_DIR/framework/.pip-version" 2>/dev/null)

main() {
    # Parse script arguments
    parse_args "$@" || exit 1
    # Download wazuh precompiled dependencies
    make -C "$WAZUH_ROOT_DIR/src" PYTHON_SOURCE=y deps -j
    if $BUILD_CPYTHON; then
        # Build CPython from sources
        rm -rf "$CPYTHON_DIR"
        download_cpython
        customize_cpython
        # Replace the default pip version if specified
        if [ -n "$PIP_VERSION" ]; then
            replace_default_pip_version $PIP_VERSION
        fi
        build_cpython
    fi

    if $BUILD_DEPS; then
        # Build wheels in arg flag was set or python was built
        download_wheels
    fi

    mimic_full_wazuh_installation
    generate_artifacts
}

generate_artifacts() {
    # Compress built cpython
    cd $WAZUH_ROOT_DIR/src/external && tar -zcf cpython_$ARCH.tar.gz --owner=0 --group=0 cpython
    # Compress ready-to-use CPython
    cd /var/ossec/framework/python && tar -zcf cpython.tar.gz --owner=0 --group=0 .
}
download_cpython() {
    git clone --branch "v$PYTHON_VERSION" --depth 1 https://github.com/python/cpython.git "$CPYTHON_DIR"
}

replace_default_pip_version() {
    local pip_version=$1
    # Replace pip version in ensurepip
    sed -i "s/^_PIP_VERSION = .*/_PIP_VERSION = \"$pip_version\"/" "$CPYTHON_DIR/Lib/ensurepip/__init__.py"
    # Remove existing pip wheel
    rm -f "$CPYTHON_DIR/Lib/ensurepip/_bundled/pip-"*.whl
    # Download specified pip wheel
    wget -O "$CPYTHON_DIR/Lib/ensurepip/_bundled/pip-$pip_version-py3-none-any.whl" "https://files.pythonhosted.org/packages/py3/p/pip/pip-$pip_version-py3-none-any.whl"
}

customize_cpython() {
    # Apply customizations
    # WIP
}

build_cpython() {
    make -j -C "$WAZUH_ROOT_DIR/src" external INSTALLDIR=$WAZUH_INSTALLDIR OPTIMIZE_CPYTHON=yes
    make -j -C "$WAZUH_ROOT_DIR/src" build_python INSTALLDIR=$WAZUH_INSTALLDIR
}

mimic_full_wazuh_installation() {
    # Install only libwazuhext to avoid full server compilation & installation
    mkdir -p $WAZUH_INSTALLDIR/lib
    install -m 0750 -o root -g wazuh libwazuhext.so $WAZUH_INSTALLDIR/lib
    # Install python interpreter and its dependencies
    make install_dependencies -j INSTALLDIR=$WAZUH_INSTALLDIR
}

download_wheels() {
    # Create dependencies directory
    mkdir -p "$CPYTHON_DIR/Dependencies"
    # Download wheels
    python3 -m pip download --requirement "$WAZUH_ROOT_DIR/framework/requirements.txt" --only-binary=:all: --dest "$CPYTHON_DIR/Dependencies"  --python-version "$PYTHON_VERSION" --no-cache-dir
    # Create index
    python3 -m pip install piprepo && piprepo build "$CPYTHON_DIR/Dependencies"
}

parse_args() {
    BUILD_CPYTHON=false
    BUILD_DEPS=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --build-cpython)
                BUILD_CPYTHON=true
                ;;
            --build-deps)
                BUILD_DEPS=true
                ;;
            *)
                echo "Error: parámetro no reconocido: $1" >&2
                return 1
                ;;
        esac
        shift
    done
}

main "$@"