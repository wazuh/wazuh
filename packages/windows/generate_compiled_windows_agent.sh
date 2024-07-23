#! /bin/bash
set -ex

BRANCH=""
JOBS="4"
ZIP_NAME=""
DEBUG="no"
OUTDIR="$(pwd)"
TRUST_VERIFICATION="1"
BUILD_DOCKER="yes"
DOCKER_TAG="latest"
CA_NAME="DigiCert Assured ID Root CA"
CUSTOM_CODE_VOL=""
DOCKERFILE_PATH="./"
DOCKER_IMAGE_NAME="compile_windows_agent"
TAG=$1


help() {
    set +x
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Optional] Select Git branch to compile Wazuh code."
    echo "    --sources <path>          [Optional] Absolute path containing wazuh source code. This option will use local source code instead of downloading it from GitHub. By default: '../../src'."
    echo "    -o, --output <rev>        [Required] Name to the output package."
    echo "    -j, --jobs <number>       [Optional] Change number of parallel jobs when compiling the Windows agent. By default: 4."
    echo "    -s, --store <path>        [Optional] Set the directory where the package will be stored. By default the current path."
    echo "    -d, --debug               [Optional] Build the binaries with debug symbols. By default: no."
    echo "    -t, --trust_verification  [Optional] Build the binaries with trust load images verification. By default: 1 (only warnings)."
    echo "    -c, --ca_name <CA name>   [Optional] CA name to be used to verify the trust of the agent. By default: DigiCert Assured ID Root CA."
    echo "    --dont-build-docker       [Optional] Locally built docker image will be used instead of generating a new one."
    echo "    --tag                     [Optional] Tag to use with the docker image."
    echo "    -h, --help                Show this help."
    echo
    exit $1
}


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
        "-j"|"--jobs")
            if [ -n "$2" ]; then
                JOBS="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-o"|"--output")
            if [ -n "$2" ]; then
                ZIP_NAME="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-d"|"--debug")
            DEBUG="yes"
            shift 1
            ;;
        "-s"|"--store")
            if [ -n "$2" ]; then
                OUTDIR="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-t"|"--trust_verification")
            if [ -n "$2" ]; then
                TRUST_VERIFICATION="$2"
                shift 2
            else
                help 1
            fi
            ;;
        "-c"|"--ca_name")
            if [ -n "$2" ]; then
                CA_NAME="$2"
                shift 2
            else
                help 1
            fi
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
        "--sources")
            if [ -n "$2" ]; then
                CUSTOM_CODE_VOL="-v $2:/local-src:Z"
                shift 2
            else
                help 1
            fi
            ;;
        *)
            help 1
        esac
    done

    if [ -z "${ZIP_NAME}" ]; then
        help |grep -B5 --color "^.*--output.*$" & exit 1
    fi

    if [ ! -d "${OUTDIR}" ]; then
        echo "Creating building directory at ${OUTDIR}"
        mkdir -p ${OUTDIR}
    fi

    if [ -z "${CUSTOM_CODE_VOL}" ]; then
        cd ../..
        CUSTOM_CODE_VOL="-v $(pwd):/local-src:Z"
        cd packages/windows
    fi

    if [[ ${BUILD_DOCKER} == "yes" ]]; then
        docker build -t ${DOCKER_IMAGE_NAME}:${DOCKER_TAG} ./ || exit 1
    fi

    if [ -n "${BRANCH}" ]; then
        ENV_BRANCH="-e BRANCH=${BRANCH}"
    fi

    docker run --rm -v ${OUTDIR}:/shared ${CUSTOM_CODE_VOL} ${ENV_BRANCH} ${DOCKER_IMAGE_NAME}:${DOCKER_TAG} ${JOBS} ${DEBUG} ${ZIP_NAME} ${TRUST_VERIFICATION} "${CA_NAME}" || exit 1
    echo "Package $(ls -Art ${OUTDIR} | tail -n 1) added to ${OUTDIR}."

    exit 0
}

main "$@"
