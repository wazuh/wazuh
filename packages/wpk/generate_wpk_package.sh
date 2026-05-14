#!/bin/bash

# Program to build the Wazuh WPK packages
# Wazuh package generator
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

CURRENT_PATH="$( cd $(dirname ${0}) ; pwd -P )"
COMMON_BUILDER="common_wpk_builder"
COMMON_BUILDER_DOCKERFILE="${CURRENT_PATH}/common"
CHECKSUM="no"

trap ctrl_c INT


function pack_wpk() {
    local BRANCH="${1}"
    local DESTINATION="${2}"
    local CONTAINER_NAME="${3}"
    local PACKAGE_NAME="${4}"
    local OUT_NAME="${5}"
    local CHECKSUM="${6}"
    local AWS_REGION="${7}"
    local WPK_KEY="${8}"
    local WPK_CERT="${9}"

    if [[ "${CHECKSUM}" == "yes" ]]; then
        CHECKSUM_FLAG="-c"
    fi
    if [ -n "${KEYDIR}" ]; then
        MOUNT_KEYDIR_FLAG="-v ${KEYDIR}:/etc/wazuh:Z"
    fi
    if [ -n "${WPK_KEY}" ]; then
        WPK_KEY_FLAG="--aws-wpk-key ${WPK_KEY}"
    fi
    if [ -n "${WPK_CERT}" ]; then
        WPK_CERT_FLAG="--aws-wpk-cert ${WPK_CERT}"
    fi

    docker run -t --rm ${MOUNT_KEYDIR_FLAG} -v ${DESTINATION}:/var/local/wazuh:Z -v ${PKG_PATH}:/var/pkg:Z -v ${DESTINATION}:/var/local/checksum:Z \
        -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
        ${CONTAINER_NAME}:${DOCKER_TAG} -b ${BRANCH} -o ${OUT_NAME} --aws-wpk-key-region ${AWS_REGION} ${WPK_KEY_FLAG} ${WPK_CERT_FLAG} -pn ${PACKAGE_NAME} ${CHECKSUM_FLAG}

    return $?
}


function build_container() {
    local CONTAINER_NAME="${1}"
    local DOCKERFILE_PATH="${2}"

    cp run.sh wpkpack.py ${DOCKERFILE_PATH}
    docker build -t ${CONTAINER_NAME}:${DOCKER_TAG} ${DOCKERFILE_PATH}
}


function help() {
    echo
    echo "Usage: ${0} [OPTIONS]"
    echo "It is required to use -k or --aws-wpk-key, --aws-wpk-cert parameters"
    echo
    echo "    -t,   --target-system <target> [Required] Select target wpk to build [linux/windows/macos]."
    echo "    -b,   --branch <branch>        [Required] Select Git branch."
    echo "    -d,   --destination <path>     [Required] Set the destination path of package."
    echo "    -pn,  --package-name <name>    [Required] Path to package file (rpm, deb, apk, msi, pkg) to pack in wpk."
    echo "    -o,   --output <name>          [Required] Name to the output package."
    echo "    -k,   --key-dir <path>         [Optional] Set the WPK key path to sign package."
    echo "    --aws-wpk-key                  [Optional] AWS Secrets manager Name/ARN to get WPK private key."
    echo "    --aws-wpk-cert                 [Optional] AWS secrets manager Name/ARN to get WPK certificate."
    echo "    --aws-wpk-key-region           [Optional] AWS Region where secrets are stored."
    echo "    -c,   --checksum               [Optional] Generate checksum on destination folder. By default: no."
    echo "    --dont-build-docker            [Optional] Locally built docker image will be used instead of generating a new one. By default: yes."
    echo "    --tag <name>                   [Optional] Tag to use with the docker image."
    echo "    -h,   --help                   Show this help."
    echo
    exit ${1}
}


function clean() {
    local DOCKERFILE_PATH="${1}"
    local exit_code="${2}"

    rm -f ${DOCKERFILE_PATH}/*.sh ${DOCKERFILE_PATH}/wpkpack.py

    return 0
}


ctrl_c() {
    clean 1
}


function main() {
    local TARGET=""
    local BRANCH=""
    local DESTINATION="${CURRENT_PATH}/output"
    local CONTAINER_NAME=""
    local PKG_NAME=""
    local OUT_NAME=""
    local WPK_KEY=""
    local WPK_CERT=""
    local AWS_REGION="us-east-1"
    local BUILD_DOCKER="yes"
    local DOCKER_TAG="latest"

    local HAVE_BRANCH=false
    local HAVE_DESTINATION=false
    local HAVE_TARGET=false
    local HAVE_KEYDIR=false
    local HAVE_PKG_NAME=false
    local HAVE_OUT_NAME=false
    local HAVE_WPK_KEY=false
    local HAVE_WPK_CERT=false

    while [ -n "${1}" ]
    do
        case "${1}" in
        "-t"|"--target-system")
            if [ -n "${2}" ]; then
                if [[ "${2}" == "linux" || "${2}" == "windows" || "${2}" == "macos" ]]; then
                    local TARGET="${2}"
                    local HAVE_TARGET=true
                    shift 2
                else
                    echo "Target system must be linux, windows or macos"
                    help 1
                fi
            else
                echo "ERROR: Missing target system."
                help 1
            fi
            ;;
        "-b"|"--branch")
            if [ -n "${2}" ]; then
                local BRANCH="${2}"
                local HAVE_BRANCH=true
                shift 2
            else
                echo "ERROR: Missing branch."
                help 1
            fi
            ;;
        "-d"|"--destination")
            if [ -n "${2}" ]; then
                local DESTINATION="${2}"
                local HAVE_DESTINATION=true
                shift 2
            else
                echo "ERROR: Missing destination directory."
                help 1
            fi
            ;;
        "-k"|"--key-dir")
            if [ -n "${2}" ]; then
                if [[ "${2: -1}" != "/" ]]; then
                    KEYDIR="${2}/"
                    local HAVE_KEYDIR=true
                else
                    KEYDIR="${2}"
                    local HAVE_KEYDIR=true
                fi
                shift 2
            fi
            ;;
        "-pn"|"--package-name")
            if [ -n "${2}" ]; then
                local HAVE_PKG_NAME=true
                local PKG_NAME="${2}"
                PKG_PATH=`echo ${PKG_NAME}| rev|cut -d'/' -f2-|rev`
                PKG_NAME=`basename ${PKG_NAME}`
                shift 2
            else
                echo "ERROR: Missing package file"
                help 1
            fi
            ;;
        "-o"|"--output")
            if [ -n "${2}" ]; then
                local HAVE_OUT_NAME=true
                local OUT_NAME="${2}"
                shift 2
            else
                echo "ERROR: Missing output name."
                help 1
            fi
            ;;
        "--aws-wpk-key")
            if [ -n "${2}" ]; then
                local HAVE_WPK_KEY=true
                local WPK_KEY="${2}"
                shift 2
            fi
            ;;
        "--aws-wpk-cert")
            if [ -n "${2}" ]; then
                local HAVE_WPK_CERT=true
                local WPK_CERT="${2}"
                shift 2
            fi
            ;;
        "--aws-wpk-key-region")
            if [ -n "${2}" ]; then
                local AWS_REGION="${2}"
                shift 2
            fi
            ;;
        "-c"|"--checksum")
            local CHECKSUM="yes"
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
        "-h"|"--help")
            help 0
            ;;
        *)
            help 1
        esac
    done

    if [[ "${HAVE_KEYDIR}" == false && ("${HAVE_WPK_KEY}" == false || "${HAVE_WPK_CERT}" == false) ]]; then
        echo "ERROR: Option -k or -wk, -wc must be set."
        help 1
    fi

    if [[ "${HAVE_TARGET}" == true ]] && [[ "${HAVE_BRANCH}" == true ]] && [[ "${HAVE_DESTINATION}" == true ]] && [[ "${HAVE_OUT_NAME}" == true ]]; then
        if [[ "${TARGET}" == "linux" || "${TARGET}" == "windows" || "${TARGET}" == "macos" ]]; then
            if [[ "${HAVE_PKG_NAME}" == true ]]; then
                if [[ "${BUILD_DOCKER}" == "yes" ]]; then
                    build_container ${COMMON_BUILDER} ${COMMON_BUILDER_DOCKERFILE} || clean ${COMMON_BUILDER_DOCKERFILE} 1
                fi
                local CONTAINER_NAME="${COMMON_BUILDER}"
                pack_wpk ${BRANCH} ${DESTINATION} ${CONTAINER_NAME} ${PKG_NAME} ${OUT_NAME} ${CHECKSUM} ${CHECKSUMDIR} ${AWS_REGION} ${WPK_KEY} ${WPK_CERT} || clean ${COMMON_BUILDER_DOCKERFILE} 1
                clean ${COMMON_BUILDER_DOCKERFILE} 0
            else
                echo "ERROR: Cannot build WPK without a package."
                help 1
            fi
        else
            echo "ERROR: Target system must be linux, windows or macos."
            help 1
        fi
    else
        echo "ERROR: Need more parameters"
        help 1
    fi

    return 0
}

main "$@"
