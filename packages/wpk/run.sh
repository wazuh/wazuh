#!/bin/bash
set -x
DIRECTORY="wazuh*"
REPOSITORY="https://github.com/wazuh/wazuh"
REFERENCE=""
JOBS="4"
OUT_NAME=""
CHECKSUM="no"
INSTALLATION_PATH="/var/ossec"
PKG_NAME=""
HAVE_PKG_NAME_WIN=false
HAVE_PKG_NAME_MAC=false
AWS_REGION="us-east-1"
KEYPATH="/etc/wazuh"
WPKCERT="${KEYPATH}/wpkcert.pem"
WPKKEY="${KEYPATH}/wpkcert.key"
OUTDIR="/var/local/wazuh"
CHECKSUMDIR="/var/local/checksum"
REVISION="1"

if command -v python3 > /dev/null ; then
    PYTHON="python3"
else
    PYTHON=""
fi

help() {
    echo
    echo "Usage: ${0} [OPTIONS]"
    echo "It is required to use -k or --aws-wpk-key, --aws-wpk-cert parameters"
    echo
    echo "    -b,   --branch <branch>      [Required] Select Git branch or tag e.g. master"
    echo "    -o,   --output <name>        [Required] Name to the output package."
    echo "    -pn,  --package-name <name>  [Required for windows and macos] Package name to pack on wpk."
    echo "    -r,   --revision <rev>       [Optional] Revision of the package. By default: 1."
    echo "    -p,   --path <path>          [Optional] Installation path for the package. By default: /var."
    echo "    -j,   --jobs <number>        [Optional] Number of parallel jobs when compiling."
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
                REFERENCE="$(echo ${2} | cut -d'/' -f2)"
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
        "-r"|"--revision")
            if [ -n "${2}" ]; then
                REVISION="${2}"
                shift 2
            fi
            ;;
        "-p"|"--path")
            if [ -n "${2}" ]; then
                INSTALLATION_PATH="${2}"
                shift 2
            fi
            ;;
        "-pn"|"--package-name")
            if [ -n "${2}" ]; then
                PKG_NAME="${2}"
                if [ "${PKG_NAME: -4}" == ".msi" ]; then
                    HAVE_PKG_NAME_WIN=true
                elif [ "${PKG_NAME: -4}" == ".pkg" ]; then
                    HAVE_PKG_NAME_MAC=true
                fi
                shift 2
            fi
            ;;
        "-j"|"--jobs")
            if [ -n "${2}" ]; then
                JOBS="${2}"
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


    NO_COMPILE=false
    # Get Wazuh
    curl -sL ${REPOSITORY}/tarball/${REFERENCE} | tar zx
    cd ${DIRECTORY}

    # Get info
    . src/init/dist-detect.sh
    VERSION=$(cat src/VERSION)
    SHORT_VERSION=$(cat src/VERSION | cut -dv -f2)
    ARCH=$(uname -m)

    # Create package
    if [ -z "${OUTPUT}" ]
    then
        if [ "${DIST_NAME}" = "centos" ]
        then
            BUILD_TARGET="agent"
            NO_COMPILE=false
        else
            BUILD_TARGET="winagent"
            NO_COMPILE=true
        fi
        OUTPUT="${OUTDIR}/${OUT_NAME}"

        mkdir -p ${OUTDIR}
    fi

    WAZUH_VERSION=$(cat src/VERSION)
    MAJOR=$(echo ${WAZUH_VERSION} | cut -dv -f2 | cut -d. -f1)
    MINOR=$(echo ${WAZUH_VERSION} | cut -d. -f2)

    if [ "${NO_COMPILE}" == false ]; then
        # Execute gmake deps if the version is greater or equal to 3.5
        if [[ ${MAJOR} -ge 4 || (${MAJOR} -ge 3 && ${MINOR} -ge 5) ]]; then
            make -C src deps TARGET=${BUILD_TARGET}
        fi

        # Compile agent
        make -C src -j ${JOBS} TARGET=${BUILD_TARGET} || exit 1
        # Clean unuseful files
        clean
        # Preload vars for installer
        preload
    fi

    # Compress and sign package
    if [ "${DIST_NAME}" = "centos" ]; then
        ${PYTHON} /usr/local/bin/wpkpack ${OUTPUT} ${WPKCERT} ${WPKKEY} *
    else

      if [ "${HAVE_PKG_NAME_WIN}" == true ]; then
          CURRENT_DIR=$(pwd)
          echo "wpkpack ${OUTPUT} ${WPKCERT} ${WPKKEY} ${PKG_NAME} upgrade.bat do_upgrade.ps1"
          cd ${OUTDIR}
          cp ${CURRENT_DIR}/src/win32/{upgrade.bat,do_upgrade.ps1} .
          cp /var/pkg/${PKG_NAME} ${OUTDIR} 2>/dev/null
          wpkpack ${OUTPUT} ${WPKCERT} ${WPKKEY} ${PKG_NAME} upgrade.bat do_upgrade.ps1
          rm -f upgrade.bat do_upgrade.ps1 ${PKG_NAME}
      elif [ "${HAVE_PKG_NAME_MAC}" == true ]; then
          CURRENT_DIR=$(pwd)
          echo "wpkpack ${OUTPUT} ${WPKCERT} ${WPKKEY} ${PKG_NAME} upgrade.sh pkg_installer_mac.sh"
          cd ${OUTDIR}
          cp ${CURRENT_DIR}/src/init/pkg_installer_mac.sh .
          cp ${CURRENT_DIR}/upgrade.sh .
          cp /var/pkg/${PKG_NAME} ${OUTDIR} 2>/dev/null
          wpkpack ${OUTPUT} ${WPKCERT} ${WPKKEY} ${PKG_NAME} upgrade.sh pkg_installer_mac.sh
          rm -f upgrade.sh pkg_installer_mac.sh ${PKG_NAME}
      else
          echo "ERROR: MSI/PKG package is needed to build the Windows or macOS WPK"
          help 1
      fi
    fi
    echo "PACKED FILE -> ${OUTPUT}"
    cd ${OUTDIR}
    if [[ ${CHECKSUM} == "yes" ]]; then
        mkdir -p ${CHECKSUMDIR}
        sha512sum "${OUT_NAME}" > "${CHECKSUMDIR}/${OUT_NAME}.sha512"
    fi
}

clean() {
    rm -rf ./{api,framework}
    rm -rf doc gen_ossec.sh add_localfiles.sh Jenkinsfile*
    rm -rf src/{addagent,analysisd,client-agent,config,error_messages,external/*}
    rm -rf src/{headers,logcollector,monitord,os_auth,os_crypto,os_csyslogd}
    rm -rf src/{os_dbd,os_execd,os_integrator,os_maild,os_net,os_regex,os_xml,os_zlib}
    rm -rf src/{remoted,reportd,shared,unit_tests,wazuh_db}

    # Clean syscheckd folder
    find src/syscheckd -type f -not -name "wazuh-syscheckd" -not -name "libfimdb.dylib" -not -name "libfimdb.so" -delete


    if [[ "${BUILD_TARGET}" != "winagent" ]]; then
        rm -rf src/win32
    fi

    rm -rf src/*.a

    find etc/templates/config -not -name "sca.files" -delete 2>/dev/null
    find etc/templates/* -maxdepth 0 -not -name "en" -not -name "config" | xargs rm -rf
}

preload() {
    echo 'USER_UPDATE="y"' > etc/preloaded-vars.conf
    echo 'USER_LANGUAGE="en"' >> etc/preloaded-vars.conf
    echo 'USER_NO_STOP="y"' >> etc/preloaded-vars.conf
    echo 'USER_BINARYINSTALL="y"'>> etc/preloaded-vars.conf
    if [[ "${BUILD_TARGET}" != "winagent" ]]; then
        echo 'USER_INSTALL_TYPE="agent"' >> etc/preloaded-vars.conf
    else
        echo 'USER_INSTALL_TYPE="winagent"' >> etc/preloaded-vars.conf
    fi
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]
then
    main "$@"
fi
