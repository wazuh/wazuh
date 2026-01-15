#!/bin/bash

set -e
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
WAZUH_PATH="$(cd $CURRENT_PATH/../../..; pwd -P)"
ARCHITECTURE="amd64"
OUTDIR="${CURRENT_PATH}/output"
BRANCH=""
JOBS="2"
DEBUG="no"
BUILD_DOCKER="yes"
DOCKER_TAG="latest"
BUILD_TYPE="release"

trap ctrl_c INT

clean() {
    exit_code=$1
    exit ${exit_code}
}

ctrl_c() {
    clean 1
}

build_standalone() {
    # Determine package architecture based on input
    case "${ARCHITECTURE}" in
        amd64|x86_64)
            PACKAGE_ARCH="amd64"
            ;;
        arm64|aarch64)
            PACKAGE_ARCH="arm64"
            ;;
        *)
            echo "Unsupported architecture: ${ARCHITECTURE}"
            return 1
            ;;
    esac

    CONTAINER_NAME="pkg_rpm_manager_builder_${PACKAGE_ARCH}"

    # Build the Docker image if needed
    if [[ ${BUILD_DOCKER} == "yes" ]]; then
        DOCKERFILE_PATH="${WAZUH_PATH}/packages/rpms/${PACKAGE_ARCH}/manager"
        if [ ! -d "${DOCKERFILE_PATH}" ]; then
            echo "Error: Dockerfile path not found: ${DOCKERFILE_PATH}"
            return 1
        fi

        # Copy the necessary files for Docker build
        echo "Copying necessary files for Docker build..."
        cp ${WAZUH_PATH}/packages/build.sh ${DOCKERFILE_PATH}
        cp ${WAZUH_PATH}/packages/rpms/utils/* ${DOCKERFILE_PATH}

        echo "Building Docker image ${CONTAINER_NAME}:${DOCKER_TAG}..."
        docker build -t ${CONTAINER_NAME}:${DOCKER_TAG} ${DOCKERFILE_PATH} || return 1

        # Clean up copied files
        find "${DOCKERFILE_PATH}" \( -name 'build.sh' -o -name 'helper_function.sh' -o -name 'build_deps.sh' \) -exec rm -f {} +
    fi

    # Set build type
    if [[ ${DEBUG} == "yes" ]]; then
        BUILD_TYPE="debug"
    else
        BUILD_TYPE="release"
    fi

    # Build the standalone package with a Docker container
    echo "Building Wazuh Engine Standalone package..."
    docker run --entrypoint /workspace/wazuh/src/engine/standalone/docker-entrypoint.sh \
        -e BUILD_TYPE="${BUILD_TYPE}" \
        -t --rm -v ${WAZUH_PATH}:/workspace/wazuh:Z \
        ${CONTAINER_NAME}:${DOCKER_TAG} || return 1

    # Get version
    VERSION="$(grep '"version"' ${WAZUH_PATH}/VERSION.json | sed -E 's/.*"version": *"([^"]+)".*/\1/')"

    # Create output directory if it doesn't exist
    mkdir -p ${OUTDIR}

    # Generate engine schemas
    echo "Generating engine schemas..."
    python3 ${WAZUH_PATH}/src/engine/tools/engine-schema/engine_schema.py generate \
        --output-dir ${WAZUH_PATH}/src/engine/ruleset/schemas/ \
        --wcs-path ${WAZUH_PATH}/src/external/wcs-flat-files/ \
        --decoder-template ${WAZUH_PATH}/src/engine/ruleset/schemas/wazuh-decoders.template.json || return 1

    # Create standalone package structure
    echo "Creating standalone package structure..."
    TEMP_DIR="${OUTDIR}/wazuh-engine-standalone-${VERSION}"
    rm -rf ${TEMP_DIR}

    install -d -m 770 \
        ${TEMP_DIR}/bin/lib \
        ${TEMP_DIR}/default-security-policy \
        ${TEMP_DIR}/data/store \
        ${TEMP_DIR}/data/kvdb \
        ${TEMP_DIR}/data/tzdb \
        ${TEMP_DIR}/data/cti \
        ${TEMP_DIR}/schemas \
        ${TEMP_DIR}/logs \
        ${TEMP_DIR}/sockets

    # Create .keep files
    touch ${TEMP_DIR}/bin/lib/.keep
    touch ${TEMP_DIR}/default-security-policy/.keep
    touch ${TEMP_DIR}/data/kvdb/.keep
    touch ${TEMP_DIR}/data/tzdb/.keep
    touch ${TEMP_DIR}/data/cti/.keep
    touch ${TEMP_DIR}/logs/.keep
    touch ${TEMP_DIR}/sockets/.keep

    # Copy schemas (flat layout: / encoded as %2F)
    cp -r ${WAZUH_PATH}/src/engine/ruleset/schemas/engine-schema.json "${TEMP_DIR}/data/store/schema%2Fengine-schema%2F0.json"
    cp -r ${WAZUH_PATH}/src/engine/ruleset/schemas/wazuh-logpar-overrides.json "${TEMP_DIR}/data/store/schema%2Fwazuh-logpar-overrides%2F0.json"
    cp -r ${WAZUH_PATH}/src/engine/ruleset/schemas/allowed-fields.json "${TEMP_DIR}/data/store/schema%2Fallowed-fields%2F0.json"
    cp -r ${WAZUH_PATH}/src/engine/ruleset/schemas/wazuh-decoders.json ${TEMP_DIR}/schemas/
    cp -r ${WAZUH_PATH}/src/engine/ruleset/schemas/wazuh-filters.json ${TEMP_DIR}/schemas/

    # Copy scripts and README
    cp -r ${WAZUH_PATH}/src/engine/standalone/run_engine.sh ${TEMP_DIR}/
    chmod +x ${TEMP_DIR}/run_engine.sh
    cp ${WAZUH_PATH}/src/engine/standalone/README.md ${TEMP_DIR}/

    # Copy libraries and binaries
    cp ${WAZUH_PATH}/src/external/rocksdb/build/librocksdb.so.8 ${TEMP_DIR}/bin/lib
    cp ${WAZUH_PATH}/src/libwazuhext.so ${TEMP_DIR}/bin/lib
    cp ${WAZUH_PATH}/src/build/shared_modules/indexer_connector/libindexer_connector.so ${TEMP_DIR}/bin/lib
    cp ${WAZUH_PATH}/src/build/shared_modules/content_manager/libcontent_manager.so ${TEMP_DIR}/bin/lib
    cp ${WAZUH_PATH}/gcc-libs/libstdc++.so.6* ${TEMP_DIR}/bin/lib/
    cp ${WAZUH_PATH}/src/build/engine/wazuh-engine ${TEMP_DIR}/bin/
    chmod +x ${TEMP_DIR}/bin/wazuh-engine

    # Create zip package
    PACKAGE_NAME="wazuh-engine-${VERSION}-linux-${ARCHITECTURE}.tar.gz"
    echo "Creating package: ${PACKAGE_NAME}"
    cd ${OUTDIR}
    tar czf ${PACKAGE_NAME} wazuh-engine-standalone-${VERSION}/ || return 1

    echo "Package created successfully: ${OUTDIR}/${PACKAGE_NAME}"

    # Clean up temp directory
    rm -rf ${TEMP_DIR}

    return 0
}

build() {
    build_standalone || return 1
    return 0
}

help() {
    set +x
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -b, --branch <branch>      [Optional] Select Git branch (not used in local build)."
    echo "    -a, --architecture <arch>  [Optional] Target architecture of the package [amd64/x86_64/arm64/aarch64]. By default: amd64."
    echo "    -j, --jobs <number>        [Optional] Change number of parallel jobs when compiling. By default: 2."
    echo "    -s, --store <path>         [Optional] Set the destination path of package. By default, an output folder will be created."
    echo "    -d, --debug                [Optional] Build the binaries with debug flags (without optimizations). By default: no."
    echo "    --dont-build-docker        [Optional] Locally built docker image will be used instead of generating a new one."
    echo "    --tag                      [Optional] Tag to use with the docker image. By default: latest."
    echo "    -h, --help                 Show this help."
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
        "-d"|"--debug")
            DEBUG="yes"
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
                OUTDIR=$(echo "$2" | sed 's:/*$::')
                shift 2
            else
                help 1
            fi
            ;;
        *)
            help 1
        esac
    done

    build && clean 0
    clean 1
}

main "$@"
