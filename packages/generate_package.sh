#!/bin/bash

# Wazuh package generator
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
WAZUH_PATH="$(cd $CURRENT_PATH/..; pwd -P)"
ARCHITECTURE="amd64"
SYSTEM="deb"
OUTDIR="${CURRENT_PATH}/output/"
BRANCH=""
REVISION="0"
JOBS="2"
DEBUG="no"
SRC="no"
BUILD_DOCKER="yes"
DOCKER_TAG="latest"
INSTALLATION_PATH="/"
CHECKSUM="no"
FUTURE="no"
IS_STAGE="no"


trap ctrl_c INT

clean() {
    exit_code=$1

    # Clean the files
    find "${DOCKERFILE_PATH}" \( -name '*.sh' -o -name '*.tar.gz' -o -name 'wazuh-*' \) ! -name 'docker_builder.sh' -exec rm -rf {} +

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

    CONTAINER_NAME="pkg_${SYSTEM}_server_builder_${ARCHITECTURE}"
    DOCKERFILE_PATH="${CURRENT_PATH}/${SYSTEM}s/${ARCHITECTURE}"

    # Copy the necessary files
    cp ${CURRENT_PATH}/build.sh ${DOCKERFILE_PATH}
    cp ${CURRENT_PATH}/${SYSTEM}s/utils/* ${DOCKERFILE_PATH}
    cp ${CURRENT_PATH}/../src/engine/vcpkg.json ${DOCKERFILE_PATH}
    cp ${CURRENT_PATH}/../src/engine/vcpkg-configuration.json ${DOCKERFILE_PATH}

    # Build the Docker image
    if [[ ${BUILD_DOCKER} == "yes" ]]; then
        docker build -t ${CONTAINER_NAME}:${DOCKER_TAG} ${DOCKERFILE_PATH} || return 1
    fi

    # Build the Debian package with a Docker container
    docker run -t --rm -v ${OUTDIR}:/var/local/wazuh:Z \
        -e SYSTEM="$SYSTEM" \
        -e ARCHITECTURE_TARGET="${ARCHITECTURE}" \
        -e INSTALLATION_PATH="${INSTALLATION_PATH}" \
        -e IS_STAGE="${IS_STAGE}" \
        -e WAZUH_BRANCH="${BRANCH}" \
        ${CUSTOM_CODE_VOL} \
        ${CONTAINER_NAME}:${DOCKER_TAG} \
        ${REVISION} ${JOBS} ${DEBUG} \
        ${CHECKSUM} ${FUTURE} ${SRC}|| return 1

    echo "Package $(ls -Art ${OUTDIR} | tail -n 1) added to ${OUTDIR}."

    return 0
}

build() {
    build_pkg  || return 1
    return 0
}

help() {
    set +x
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>      [Optional] Select Git branch."
    echo "    -a, --architecture <arch>  [Optional] Target architecture of the package [amd64/arm64]."
    echo "    -j, --jobs <number>        [Optional] Change number of parallel jobs when compiling the manager or agent. By default: 2."
    echo "    -r, --revision <rev>       [Optional] Package revision. By default: 0."
    echo "    -s, --store <path>         [Optional] Set the destination path of package. By default, an output folder will be created."
    echo "    -p, --path <path>          [Optional] Installation path for the package. By default: /var/wazuh-server."
    echo "    -d, --debug                [Optional] Build the binaries with debug symbols. By default: no."
    echo "    -c, --checksum             [Optional] Generate checksum on the same directory than the package. By default: no."
    echo "    --dont-build-docker        [Optional] Locally built docker image will be used instead of generating a new one."
    echo "    --tag                      [Optional] Tag to use with the docker image."
    echo "    --sources <path>           [Optional] Absolute path containing wazuh source code. This option will use local source code instead of downloading it from GitHub. By default use the script path."
    echo "    --is_stage                 [Optional] Use release name in package."
    echo "    --system                   [Optional] Select Package OS [rpm, deb]. By default is 'deb'."
    echo "    --src                      [Optional] Generate the source package in the destination directory."
    echo "    --future                   [Optional] Build test future package x.30.0 Used for development purposes."
    echo "    -h, --help                 Show this help."
    echo
    exit $1
}

echo "== GENERATE PACKAGE =="
echo "SYSTEM: $SYSTEM"
echo "ARCHITECTURE: $ARCHITECTURE"
echo "IS_STAGE: $IS_STAGE"
echo "CHECKSUM: $CHECKSUM"
echo "REVISION: $REVISION"
echo "DEBUG: $DEBUG"
echo "BRANCH: $BRANCH"

main() {
    while [ -n "$1" ]
    do
        case "$1" in
        "-b"|"--branch")
            if [ -n "$2" ]; then
                BRANCH="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-h"|"--help")
            help 0
            ;;
        "-a"|"--architecture")
            if [ -n "$2" ]; then
                ARCHITECTURE="$2"
                shift 2
            else
                help 1
            fi
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
        "--is_stage")
            IS_STAGE="yes"
            shift 1
            ;;
        "--src")
            SRC="yes"
            shift 1
            ;;
        "--system")
            SYSTEM="$2"
            shift 2
            ;;
        *)
            help 1
        esac
    done

    if [ -z "${CUSTOM_CODE_VOL}" ]; then
        CUSTOM_CODE_VOL="-v $WAZUH_PATH:/wazuh-local-src:Z"
    fi

    build && clean 0
    clean 1
}

main "$@"
