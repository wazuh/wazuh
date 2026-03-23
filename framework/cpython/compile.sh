#!/bin/bash
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -euo pipefail

WAZUH_HOST_DIR=/wazuh_host
WAZUH_ROOT_DIR=/wazuh #Important: Do not change this path
WAZUH_INSTALLDIR=/var/wazuh-manager
CPYTHON_DIR=$WAZUH_ROOT_DIR/src/external/cpython
OUTPUT_DIR=/output

main() {
    # Parse script arguments
    parse_args "$@" || exit 1
    # Get wazuh repository
    get_wazuh_repo
    # Download wazuh precompiled dependencies
    make -C "$WAZUH_ROOT_DIR/src" PYTHON_SOURCE=y deps -j

    PYTHON_VERSION=$(cat $WAZUH_ROOT_DIR/framework/.python-version)

    if $BUILD_CPYTHON; then
        # Build CPython from sources
        rm -rf "$CPYTHON_DIR"
        download_cpython
        customize_cpython
        build_cpython
    fi

    if $BUILD_DEPS || $BUILD_CPYTHON; then
        download_wheels
    fi

    mimic_full_wazuh_installation
    generate_artifacts
}

get_wazuh_repo() {
    if [ -z "${WAZUH_BRANCH:-}" ]; then
        cp -rf $WAZUH_HOST_DIR $WAZUH_ROOT_DIR
        # Clean previous builds
        rm -rf $WAZUH_ROOT_DIR/src/external/*
        make clean -j -C "$WAZUH_ROOT_DIR/src"
    else
        git clone --branch "$WAZUH_BRANCH" --depth 1 https://github.com/wazuh/wazuh.git  "$WAZUH_ROOT_DIR"
    fi
}

download_cpython() {
    git clone --branch "v$PYTHON_VERSION" --depth 1 https://github.com/python/cpython.git "$CPYTHON_DIR"
}

customize_cpython() {
    cp -f $WAZUH_ROOT_DIR/framework/cpython/custom/Setup.local $CPYTHON_DIR/Modules
    cp -f $WAZUH_ROOT_DIR/framework/cpython/custom/Setup.stdlib.in $CPYTHON_DIR/Modules
}

build_cpython() {
    make -j -C "$WAZUH_ROOT_DIR/src" build_python INSTALLDIR=$WAZUH_INSTALLDIR OPTIMIZE_CPYTHON=yes
}

mimic_full_wazuh_installation() {
    # Force build of libwazuhext
    make -j -C "$WAZUH_ROOT_DIR/src" external INSTALLDIR=$WAZUH_INSTALLDIR
    # Install only libwazuhext to avoid full server compilation & installation
    mkdir -p "$WAZUH_INSTALLDIR/lib"
    install -m 0750 $WAZUH_ROOT_DIR/src/build/lib/libwazuhext.so "$WAZUH_INSTALLDIR/lib"
    # Install python interpreter and its dependencies
    make -j -C "$WAZUH_ROOT_DIR/src" install_dependencies INSTALLDIR=$WAZUH_INSTALLDIR
}

generate_artifacts() {
    # Compress built cpython
    cd $WAZUH_ROOT_DIR/src/external && tar -zcf "$OUTPUT_DIR/cpython_$ARCH.tar.gz" --owner=0 --group=0 cpython
    # Compress ready-to-use CPython
    cd $WAZUH_INSTALLDIR/framework/python && tar -zcf "$OUTPUT_DIR/cpython.tar.gz" --owner=0 --group=0 .
}

download_wheels() {
    # Install Python3 to download wheels
    yum install python3 -y
    python3 -m pip install --upgrade pip
    # Remove existing dependencies
    rm -rf "$CPYTHON_DIR/Dependencies"
    # Create dependencies directory
    mkdir -p "$CPYTHON_DIR/Dependencies"
    # Download wheels
    python3 -m pip download --requirement "$WAZUH_ROOT_DIR/framework/requirements.txt"  --no-deps --dest "$CPYTHON_DIR/Dependencies"  --python-version "$PYTHON_VERSION" --no-cache-dir
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
            --wazuh-branch)
                WAZUH_BRANCH="$2"
                ;;
            *)
                echo "ERROR: Unrecognized parameter: $1" >&2
                return 1
                ;;
        esac
        shift
    done
}

main "$@"
