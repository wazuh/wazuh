#!/bin/bash
set -x
DIRECTORY="wazuh*"
REPOSITORY="https://github.com/wazuh/wazuh"
REFERENCE=""
OUT_NAME=""
CHECKSUM="no"
PKG_NAME=""
HAVE_PKG_NAME_WIN=false
HAVE_PKG_NAME_MAC=false
HAVE_PKG_NAME_LINUX=false
AWS_REGION="us-east-1"
KEYPATH="/etc/wazuh"
WPKCERT="${KEYPATH}/wpkcert.pem"
WPKKEY="${KEYPATH}/wpkcert.key"
OUTDIR="/var/local/wazuh"
CHECKSUMDIR="/var/local/checksum"


help() {
    set +x
    echo
    echo "Usage: ${0} [OPTIONS]"
    echo "It is required to use -k or --aws-wpk-key, --aws-wpk-cert parameters"
    echo
    echo "    -b,   --branch <branch>      [Required] Select Git branch or tag e.g. master"
    echo "    -o,   --output <name>        [Required] Name to the output package."
    echo "    -pn,  --package-name <name>  [Required] Path to package file (rpm, deb, apk, msi, pkg) to pack in wpk."
    echo "    -c,   --checksum             [Optional] Whether Generate checksum or not."
    echo "    --aws-wpk-key                [Optional] AWS Secrets manager Name/ARN to get WPK private key."
    echo "    --aws-wpk-cert               [Optional] AWS secrets manager Name/ARN to get WPK certificate."
    echo "    --aws-wpk-key-region         [Optional] AWS Region where secrets are stored."
    echo "    -h,   --help                 Show this help."
    echo
    exit ${1}
}

main() {
    while [ -n "${1}" ]
    do
        case "${1}" in
        "-b"|"--branch")
            if [ -n "${2}" ]; then
                REFERENCE="${2}"
                shift 2
            else
                echo "ERROR: Missing branch."
                help 1
            fi
            ;;
        "-o"|"--output")
            if [ -n "${2}" ]; then
                OUT_NAME="${2}"
                shift 2
            else
                echo "ERROR: Missing output name."
                help 1
            fi
            ;;
        "-pn"|"--package-name")
            if [ -n "${2}" ]; then
                PKG_NAME="${2}"
                if [ "${PKG_NAME: -4}" == ".msi" ]; then
                    HAVE_PKG_NAME_WIN=true
                elif [ "${PKG_NAME: -4}" == ".pkg" ]; then
                    HAVE_PKG_NAME_MAC=true
                elif [ "${PKG_NAME: -4}" == ".rpm" ]; then
                    HAVE_PKG_NAME_LINUX=true
                elif [ "${PKG_NAME: -4}" == ".deb" ]; then
                    HAVE_PKG_NAME_LINUX=true
                elif [ "${PKG_NAME: -4}" == ".apk" ]; then
                    HAVE_PKG_NAME_LINUX=true
                else
                    echo "ERROR: missing package file."
                    help 1
                fi
                shift 2
            fi
            ;;
        "-c"|"--checksum")
            CHECKSUM="yes"
            shift 1
            ;;
        "--aws-wpk-key")
            if [ -n "${2}" ]; then
                AWS_WPK_KEY="${2}"
                shift 2
            fi
            ;;
        "--aws-wpk-cert")
            if [ -n "${2}" ]; then
                AWS_WPK_CERT="${2}"
                shift 2
            fi
            ;;
        "--aws-wpk-key-region")
            if [ -n "${2}" ]; then
                AWS_REGION="${2}"
                shift 2
            fi
          ;;
        "-h"|"--help")
            help 0
            ;;
        *)
            help 1
        esac
    done

    if [ -n "${AWS_WPK_CERT}" ] && [ -n "${AWS_WPK_KEY}" ]; then
        mkdir -p ${KEYPATH}
        aws --region=${AWS_REGION} secretsmanager get-secret-value --secret-id ${AWS_WPK_CERT} | jq . > wpkcert.pem.json
        jq .SecretString wpkcert.pem.json | tr -d '"' | sed 's|\\n|\n|g' > ${WPKCERT}
        rm -f wpkcert.pem.json
        aws --region=${AWS_REGION} secretsmanager get-secret-value --secret-id ${AWS_WPK_KEY} | jq . > wpkcert.key.json
        jq .SecretString wpkcert.key.json | tr -d '"' | sed 's|\\n|\n|g' > ${WPKKEY}
        rm -f wpkcert.key.json
    fi

    # Get Wazuh
    curl -sL ${REPOSITORY}/tarball/${REFERENCE} | tar zx
    cd ${DIRECTORY}

    # Create package
    if [ -z "${OUTPUT}" ]
    then
        OUTPUT="${OUTDIR}/${OUT_NAME}"
        mkdir -p ${OUTDIR}
    fi

    # Compress and sign package
    if [ "${HAVE_PKG_NAME_WIN}" == true ]; then
        CURRENT_DIR=$(pwd)
        echo "wpkpack ${OUTPUT} ${WPKCERT} ${WPKKEY} ${PKG_NAME} upgrade.bat do_upgrade.ps1"
        cd ${OUTDIR}
        cp ${CURRENT_DIR}/src/win32/{upgrade.bat,do_upgrade.ps1} .
        cp /var/pkg/${PKG_NAME} ${OUTDIR} 2>/dev/null
        wpkpack ${OUTPUT} ${WPKCERT} ${WPKKEY} ${PKG_NAME} upgrade.bat do_upgrade.ps1
        rm -f upgrade.bat do_upgrade.ps1 ${PKG_NAME}
    elif [ "${HAVE_PKG_NAME_MAC}" == true ] || [ "${HAVE_PKG_NAME_LINUX}" == true ]; then
        CURRENT_DIR=$(pwd)
        echo "wpkpack ${OUTPUT} ${WPKCERT} ${WPKKEY} ${PKG_NAME} upgrade.sh pkg_installer.sh"
        cd ${OUTDIR}
        cp ${CURRENT_DIR}/src/init/pkg_installer.sh .
        cp ${CURRENT_DIR}/upgrade.sh .
        cp /var/pkg/${PKG_NAME} ${OUTDIR} 2>/dev/null
        wpkpack ${OUTPUT} ${WPKCERT} ${WPKKEY} ${PKG_NAME} upgrade.sh pkg_installer.sh
        rm -f upgrade.sh pkg_installer.sh ${PKG_NAME}
    else
        echo "ERROR: a package (MSI/PKG/RPM/DEB) is needed to build the WPK"
        help 1
    fi

    echo "PACKED FILE -> ${OUTPUT}"
    cd ${OUTDIR}

    if [[ ${CHECKSUM} == "yes" ]]; then
        mkdir -p ${CHECKSUMDIR}
        sha512sum "${OUT_NAME}" > "${CHECKSUMDIR}/${OUT_NAME}.sha512"
    fi
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]
then
    main "$@"
fi
