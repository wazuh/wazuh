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
LINUX_BUILDER_X86_64="linux_wpk_builder_x86_64"
LINUX_BUILDER_X86_64_DOCKERFILE="${CURRENT_PATH}/linux/x86_64"
LINUX_BUILDER_AARCH64="linux_wpk_builder_aarch64"
LINUX_BUILDER_AARCH64_DOCKERFILE="${CURRENT_PATH}/linux/aarch64"
LINUX_BUILDER_ARMV7HL="linux_wpk_builder_armv7hl"
LINUX_BUILDER_ARMV7HL_DOCKERFILE="${CURRENT_PATH}/linux/armv7hl"
COMMON_BUILDER="common_wpk_builder"
COMMON_BUILDER_DOCKERFILE="${CURRENT_PATH}/common"
CHECKSUM="no"
INSTALLATION_PATH="/var/ossec"

trap ctrl_c INT


function pack_wpk() {
    local BRANCH="${1}"
    local DESTINATION="${2}"
    local CONTAINER_NAME="${3}"
    local JOBS="${4}"
    local PACKAGE_NAME="${5}"
    local OUT_NAME="${6}"
    local CHECKSUM="${7}"
    local CHECKSUMDIR="${8}"
    local INSTALLATION_PATH="${9}"
    local AWS_REGION="${10}"
    local WPK_KEY="${11}"
    local WPK_CERT="${12}"

    if [ -n "${CHECKSUM}" ]; then
        CHECKSUM_FLAG="-c"
    fi
    if [ -n "${WPK_KEY}" ]; then
        WPK_KEY_FLAG="--aws-wpk-key ${WPK_KEY}"
    fi
    if [ -n "${WPK_CERT}" ]; then
        WPK_CERT_FLAG="--aws-wpk-cert ${WPK_CERT}"
    fi

    docker run -t --rm -v ${KEYDIR}:/etc/wazuh:Z -v ${DESTINATION}:/var/local/wazuh:Z -v ${PKG_PATH}:/var/pkg:Z \
        -v ${CHECKSUMDIR}:/var/local/checksum:Z \
        ${CONTAINER_NAME} -b ${BRANCH} -j ${JOBS} -o ${OUT_NAME} -p ${INSTALLATION_PATH} --aws-wpk-key-region ${AWS_REGION} ${WPK_KEY_FLAG} ${WPK_CERT_FLAG} -pn ${PACKAGE_NAME} ${CHECKSUM_FLAG}

    return $?
}


function build_wpk_linux() {
    local BRANCH="${1}"
    local DESTINATION="${2}"
    local CONTAINER_NAME="${3}"
    local JOBS="${4}"
    local OUT_NAME="${5}"
    local CHECKSUM="${6}"
    local CHECKSUMDIR="${7}"
    local INSTALLATION_PATH="${8}"
    local AWS_REGION="${9}"
    local WPK_KEY="${10}"
    local WPK_CERT="${11}"

    if [ -n "${CHECKSUM}" ]; then
        CHECKSUM_FLAG="-c"
    fi
    if [ -n "${WPK_KEY}" ]; then
        WPK_KEY_FLAG="--aws-wpk-key ${WPK_KEY}"
    fi
    if [ -n "${WPK_CERT}" ]; then
        WPK_CERT_FLAG="--aws-wpk-cert ${WPK_CERT}"
    fi

    docker run -t --rm -v ${KEYDIR}:/etc/wazuh:Z -v ${DESTINATION}:/var/local/wazuh:Z \
        -v ${CHECKSUMDIR}:/var/local/checksum:Z \
        ${CONTAINER_NAME} -b ${BRANCH} -j ${JOBS} -o ${OUT_NAME} -p ${INSTALLATION_PATH} --aws-wpk-key-region ${AWS_REGION} ${WPK_KEY_FLAG} ${WPK_CERT_FLAG} ${CHECKSUM_FLAG}

    return $?
}


function build_container() {
    local CONTAINER_NAME="${1}"
    local DOCKERFILE_PATH="${2}"

    cp run.sh wpkpack.py ${DOCKERFILE_PATH}
    docker build -t ${CONTAINER_NAME} ${DOCKERFILE_PATH}
}


function help() {
    echo
    echo "Usage: ${0} [OPTIONS]"
    echo "It is required to use -k or --aws-wpk-key, --aws-wpk-cert parameters"
    echo
    echo "    -t,   --target-system <target> [Required] Select target wpk to build [linux/windows/macos]"
    echo "    -b,   --branch <branch>        [Required] Select Git branch or tag e.g. $BRANCH"
    echo "    -d,   --destination <path>     [Required] Set the destination path of package."
    echo "    -pn,  --package-name <name>    [Required for windows and macos] Package name to pack on wpk."
    echo "    -o,   --output <name>          [Required] Name to the output package."
    echo "    -k,   --key-dir <path>         [Optional] Set the WPK key path to sign package."
    echo "    --aws-wpk-key                  [Optional] AWS Secrets manager Name/ARN to get WPK private key."
    echo "    --aws-wpk-cert                 [Optional] AWS secrets manager Name/ARN to get WPK certificate."
    echo "    --aws-wpk-key-region           [Optional] AWS Region where secrets are stored."
    echo "    -a,   --architecture <arch>    [Optional] Target architecture of the package [x86_64]."
    echo "    -j,   --jobs <number>          [Optional] Number of parallel jobs when compiling."
    echo "    -p,   --path <path>            [Optional] Installation path for the package. By default: /var/ossec."
    echo "    -c,   --checksum <path>        [Optional] Generate checksum on the desired path."
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
    local ARCHITECTURE="x86_64"
    local JOBS="4"
    local CONTAINER_NAME=""
    local PKG_NAME=""
    local OUT_NAME=""
    local NO_COMPILE=false
    local CHECKSUMDIR=""
    local WPK_KEY=""
    local WPK_CERT=""
    local AWS_REGION="us-east-1"

    local HAVE_BRANCH=false
    local HAVE_DESTINATION=false
    local HAVE_TARGET=false
    local HAVE_KEYDIR=false
    local HAVE_PKG_NAME=false
    local HAVE_OUT_NAME=false
    local HAVE_WPK_KEY=false
    local HAVE_WPK_CERT=false
    local LINUX_BUILDER="${LINUX_BUILDER_X86_64}"
    local LINUX_BUILDER_DOCKERFILE="${LINUX_BUILDER_X86_64_DOCKERFILE}"

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
                local BRANCH="$(echo ${2} | cut -d'/' -f2)"
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
        "-a"|"--architecture")
            if [ -n "${2}" ]; then
                if [[ "${2}" == "x86_64" ]] || [[ "${2}" == "amd64" ]]; then
                    local ARCHITECTURE="x86_64"
                    local LINUX_BUILDER="${LINUX_BUILDER_X86_64}"
                    local LINUX_BUILDER_DOCKERFILE="${LINUX_BUILDER_X86_64_DOCKERFILE}"
                    shift 2
                elif [[ "${2}" == "aarch64" ]]; then
                    local ARCHITECTURE="${2}"
                    local LINUX_BUILDER="${LINUX_BUILDER_AARCH64}"
                    local LINUX_BUILDER_DOCKERFILE="${LINUX_BUILDER_AARCH64_DOCKERFILE}"
                    shift 2
                elif [[ "${2}" == "armv7hl" ]]; then
                    local ARCHITECTURE="${2}"
                    local LINUX_BUILDER="${LINUX_BUILDER_ARMV7HL}"
                    local LINUX_BUILDER_DOCKERFILE="${LINUX_BUILDER_ARMV7HL_DOCKERFILE}"
                    shift 2
                else
                    echo "Architecture must be x86_64/amd64, aarch64 or armv7hl"
                    help 1
                fi
            else
              echo "ERROR: Missing architecture."
              help 1
            fi
            ;;
        "-j"|"--jobs")
            if [ -n "${2}" ]; then
                local JOBS="${2}"
                shift 2
            else
                echo "ERROR: Missing jobs."
                help 1
            fi
            ;;
        "-p"|"--path")
              if [ -n "${2}" ]; then
                  INSTALLATION_PATH="${2}"
                  shift 2
              else
                  help 1
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
                echo "ERROR: Missing package name"
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
            if [ -n "${2}" ]; then
                local CHECKSUMDIR="${2}"
                local CHECKSUM="yes"
                shift 2
            else
                local CHECKSUM="yes"
                shift 1
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

    if [ -z "${CHECKSUMDIR}" ]; then
        local CHECKSUMDIR="${DESTINATION}"
    fi

    if [[ "${HAVE_TARGET}" == true ]] && [[ "${HAVE_BRANCH}" == true ]] && [[ "${HAVE_DESTINATION}" == true ]] && [[ "${HAVE_OUT_NAME}" == true ]]; then
        if [[ "${TARGET}" == "windows" || "${TARGET}" == "macos" ]]; then
            if [[ "${HAVE_PKG_NAME}" == true ]]; then
                build_container ${COMMON_BUILDER} ${COMMON_BUILDER_DOCKERFILE} || clean ${COMMON_BUILDER_DOCKERFILE} 1
                local CONTAINER_NAME="${COMMON_BUILDER}"
                pack_wpk ${BRANCH} ${DESTINATION} ${CONTAINER_NAME} ${JOBS} ${PKG_NAME} ${OUT_NAME} ${CHECKSUM} ${CHECKSUMDIR} ${INSTALLATION_PATH} ${AWS_REGION} ${WPK_KEY} ${WPK_CERT} || clean ${COMMON_BUILDER_DOCKERFILE} 1
                clean ${COMMON_BUILDER_DOCKERFILE} 0
            else
                echo "ERROR: No MSI/PKG package name specified for Windows or macOS WPK"
                help 1
            fi
        else
            build_container ${LINUX_BUILDER} ${LINUX_BUILDER_DOCKERFILE} || clean ${LINUX_BUILDER_DOCKERFILE} 1
            local CONTAINER_NAME="${LINUX_BUILDER}"
            build_wpk_linux ${BRANCH} ${DESTINATION} ${CONTAINER_NAME} ${JOBS} ${OUT_NAME} ${CHECKSUM} ${CHECKSUMDIR} ${INSTALLATION_PATH} ${AWS_REGION} ${WPK_KEY} ${WPK_CERT} || clean ${LINUX_BUILDER_DOCKERFILE} 1
            clean ${LINUX_BUILDER_DOCKERFILE} 0
        fi
    else
        echo "ERROR: Need more parameters"
        help 1
    fi

    return 0
}

main "$@"
