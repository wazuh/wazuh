#! /bin/bash

BRANCH="master"
JOBS="4"
REVISION="1"
DEBUG="no"
OUTDIR="$(pwd)"
REVISION="1"
TRUST_VERIFICATION="1"
CA_NAME="DigiCert Assured ID Root CA"

DOCKERFILE_PATH="./"
DOCKER_IMAGE_NAME="compile_windows_agent"
TAG=$1


generate_compiled_win_agent() {

    if [ ! -d "${OUTDIR}" ]; then
        echo "Creating building directory at ${OUTDIR}"
        mkdir -p ${OUTDIR}
    fi

    docker build -t ${DOCKER_IMAGE_NAME} ./ || exit 1
    docker run --rm -v ${OUTDIR}:/shared ${DOCKER_IMAGE_NAME} ${BRANCH} ${JOBS} ${DEBUG} ${REVISION} ${TRUST_VERIFICATION} "${CA_NAME}" || exit 1
    echo "Package $(ls -Art ${OUTDIR} | tail -n 1) added to ${OUTDIR}."
}


help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>     [Required] Select Git branch [${BRANCH}]. By default: master."
    echo "    -j, --jobs <number>       [Optional] Change number of parallel jobs when compiling the Windows agent. By default: 4."
    echo "    -r, --revision <rev>      [Optional] Package revision. By default: 1."
    echo "    -s, --store <path>        [Optional] Set the directory where the package will be stored. By default the current path."
    echo "    -d, --debug               [Optional] Build the binaries with debug symbols. By default: no."
    echo "    -t, --trust_verification  [Optional] Build the binaries with trust load images verification. By default: 1 (only warnings)."
    echo "    -c, --ca_name <CA name>   [Optional] CA name to be used to verify the trust of the agent. By default: DigiCert Assured ID Root CA."
    echo "    -h, --help                Show this help."
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
        *)
            help 1
        esac
    done

    if [[ "$BUILD" != "no" ]]; then
        generate_compiled_win_agent || exit 1
    fi

    exit 0
}

main "$@"
