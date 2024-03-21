#!/bin/bash

# Wazuh package generator
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -x
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
ARCHITECTURE="amd64"
PACKAGE_FORMAT="deb"
OUTDIR="${CURRENT_PATH}/output/"
BRANCH=""
REVISION="0"
TARGET="agent"
JOBS="2"
DEBUG="no"
SRC="no"
BUILD_DOCKER="yes"
DOCKER_TAG="latest"
INSTALLATION_PATH="/var/ossec"
CHECKSUM="no"
FUTURE="no"
LEGACY="no"
IS_PACKAGE_RELEASE="no"


trap ctrl_c INT

clean() {
    exit_code=$1

    # Clean the files
    rm -rf ${DOCKERFILE_PATH}/{*.sh,*.tar.gz,wazuh-*} ${SOURCES_DIRECTORY}

    exit ${exit_code}
}

ctrl_c() {
    clean 1
}

download_file() {
    URL=$1
    DESTDIR=$2
    if command -v curl > /dev/null 2>&1 ; then
        (cd ${DESTDIR} && curl -sO ${URL})
    elif command -v wget > /dev/null 2>&1 ; then
        wget ${URL} -P ${DESTDIR} -q
    fi
}

build_pkg() {
    if [ "$LEGACY" = "yes" ]; then
        REVISION="${REVISION}.el5"
        TAR_URL="https://packages-dev.wazuh.com/utils/centos-5-i386-build/centos-5-i386.tar.gz"
        TAR_FILE="${CURRENT_PATH}/${PACKAGE_FORMAT}s/${ARCHITECTURE}/legacy/centos-5-i386.tar.gz"
        if [ ! -f "$TAR_FILE" ]; then
            download_file ${TAR_URL} "${CURRENT_PATH}/${PACKAGE_FORMAT}s/${ARCHITECTURE}/legacy"
        fi
        DOCKERFILE_PATH="${CURRENT_PATH}/${PACKAGE_FORMAT}s/${ARCHITECTURE}/legacy"
    else
        DOCKERFILE_PATH="${CURRENT_PATH}/${PACKAGE_FORMAT}s/${ARCHITECTURE}/${TARGET}"
    fi
    if [ "$BUILD_DOCKER" = "no" ]; then
        CONTAINER_NAME="pkg_${PACKAGE_FORMAT}_${TARGET}_builder_${ARCHITECTURE}"
    else
        CONTAINER_NAME="${PACKAGE_FORMAT}_${TARGET}_builder_${ARCHITECTURE}"
    fi
    LOCAL_SPECS="${CURRENT_PATH}/${PACKAGE_FORMAT}s"

    # Copy the necessary files
    cp ${CURRENT_PATH}/build.sh ${DOCKERFILE_PATH}
    cp ${CURRENT_PATH}/${PACKAGE_FORMAT}s/utils/* ${DOCKERFILE_PATH}

    # Build the Docker image
    if [[ ${BUILD_DOCKER} == "yes" ]]; then
        docker build -t ${CONTAINER_NAME}:${DOCKER_TAG} ${DOCKERFILE_PATH} || return 1
    fi

    # Build the Debian package with a Docker container
    docker run -t --rm -v ${OUTDIR}:/var/local/wazuh:Z \
        -v ${LOCAL_SPECS}:/specs:Z \
        -e PACKAGE_FORMAT="$PACKAGE_FORMAT" \
        -e BUILD_TARGET="${TARGET}" \
        -e ARCHITECTURE_TARGET="${ARCHITECTURE}" \
        -e INSTALLATION_PATH="${INSTALLATION_PATH}" \
        -e IS_PACKAGE_RELEASE="${IS_PACKAGE_RELEASE}" \
        ${CUSTOM_CODE_VOL} \
        ${CONTAINER_NAME}:${DOCKER_TAG} ${BRANCH} \
        ${REVISION} ${JOBS} ${DEBUG} \
        ${CHECKSUM} ${FUTURE} ${LEGACY} ${SRC}|| return 1

    echo "Package $(ls -Art ${OUTDIR} | tail -n 1) added to ${OUTDIR}."

    return 0
}

build() {
    build_pkg  || return 1
    return 0
}

help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>      [Required] Select Git branch [${BRANCH}]. By default: master."
    echo "    -t, --target <target>      [Required] Target package to build: manager or agent."
    echo "    -a, --architecture <arch>  [Optional] Target architecture of the package [amd64/i386/ppc64le/arm64/armhf]."
    echo "    -j, --jobs <number>        [Optional] Change number of parallel jobs when compiling the manager or agent. By default: 2."
    echo "    -r, --revision <rev>       [Optional] Package revision. By default: 0."
    echo "    -s, --store <path>         [Optional] Set the destination path of package. By default, an output folder will be created."
    echo "    -p, --path <path>          [Optional] Installation path for the package. By default: /var/ossec."
    echo "    -d, --debug                [Optional] Build the binaries with debug symbols. By default: no."
    echo "    -c, --checksum             [Optional] Generate checksum on the same directory than the package."
    echo "    -l, --legacy               [Optional only for RPM] Build package for CentOS 5."
    echo "    --dont-build-docker        [Optional] Locally built docker image will be used instead of generating a new one."
    echo "    --tag                      [Optional] Tag to use with the docker image."
    echo "    --sources <path>           [Optional] Absolute path containing wazuh source code. This option will use local source code instead of downloading it from GitHub."
    echo "    --release-package          [Optional] Use release name in package"
    echo "    --src                      [Optional] Generate the source package in the destination directory."
    echo "    --future                   [Optional] Build test future package x.30.0 Used for development purposes."
    echo "    -h, --help                 Show this help."
    echo
    exit $1
}


main() {
    BUILD="no"
    while [ -n "$1" ]
    do
        case "$1" in
        "-b"|"--branch")
            if [ -n "$2" ]; then
                BRANCH="$2"
                BUILD="yes"
                shift 2
            else
                help 1
            fi
            ;;
        "-h"|"--help")
            help 0
            ;;
        "-t"|"--target")
            if [ -n "$2" ]; then
                TARGET="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-a"|"--architecture")
            if [ -n "$2" ]; then
                ARCHITECTURE="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-l"|"--legacy")
            LEGACY="yes"
            shift 1
            ;;
        "-j"|"--jobs")
            if [ -n "$2" ]; then
                JOBS="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-r"|"--revision")
            if [ -n "$2" ]; then
                REVISION="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-p"|"--path")
            if [ -n "$2" ]; then
                INSTALLATION_PATH="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-d"|"--debug")
            DEBUG="yes"
            shift 1
            ;;
        "-c"|"--checksum")
            CHECKSUM="yes"
            shift 1
            ;;
        "--dont-build-docker")
            BUILD_DOCKER="no"
            shift 1
            ;;
        "--tag")
            if [ -n "$2" ]; then
                DOCKER_TAG="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-s"|"--store")
            if [ -n "$2" ]; then
                OUTDIR="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "--sources")
            if [ -n "$2" ]; then
               CUSTOM_CODE_VOL="-v $2:/wazuh-local-src:Z"
               shift 2
            else
                help 1
            fi
            ;;
        "--future")
            FUTURE="yes"
            shift 1
            ;;
        "--release-package")
            IS_PACKAGE_RELEASE="yes"
            shift 1
            ;;
        "--src")
            SRC="yes"
            shift 1
            ;;
        "--package-format")
            PACKAGE_FORMAT="$2"
            shift 2
            ;;
        *)
            help 1
        esac
    done

    if [[ "$BUILD" != "no" ]]; then
        build || clean 1
    else
        clean 1
    fi

    clean 0
}

main "$@"
