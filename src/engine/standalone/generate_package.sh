#!/bin/bash

set -e
CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
WAZUH_PATH="$(cd $CURRENT_PATH/../../..; pwd -P)"
ARCHITECTURE="amd64"
OUTDIR="${CURRENT_PATH}/output"
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

install_geoip() {
    local wazuh_path="$1"
    local temp_dir="$2"

    local geoip_src_path="${wazuh_path}/src/external/geo_db"
    local mmdb_dst_dir="${temp_dir}/data/mmdb"
    local store_doc_dir="${temp_dir}/data/store/geo/mmdb"
    local store_doc="${store_doc_dir}/0"
    local manifest_file="${geoip_src_path}/manifest.json"

    local asn_src="${geoip_src_path}/GeoLite2-ASN.mmdb"
    local city_src="${geoip_src_path}/GeoLite2-City.mmdb"

    # Ensure dirs exist (in case caller didn't create them yet)
    install -d -m 0770 "${mmdb_dst_dir}" "${store_doc_dir}"

    if [ ! -f "${asn_src}" ] || [ ! -f "${city_src}" ]; then
        echo "Warning: GeoIP .mmdb files not found in ${geoip_src_path}. Standalone will ship without GeoIP."
        return 0
    fi

    echo "Including GeoIP databases (offline) in standalone package..."

    # Copy databases into package
    install -m 0640 "${asn_src}"  "${mmdb_dst_dir}/"
    install -m 0640 "${city_src}" "${mmdb_dst_dir}/"

    # Prefer manifest.json values (same semantics as manager/install.sh),
    # but do NOT ship manifest.json in the package.
    local asn_md5=""
    local city_md5=""
    local generated_at=""

    if [ -f "${manifest_file}" ]; then
        asn_md5=$(grep -A 2 '"asn"'  "${manifest_file}" | grep '"md5"' | sed 's/.*"md5"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        city_md5=$(grep -A 2 '"city"' "${manifest_file}" | grep '"md5"' | sed 's/.*"md5"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        generated_at=$(grep '"generated_at"' "${manifest_file}" | sed 's/.*"generated_at"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/')
    fi

    # Fallbacks if manifest missing/partial (keeps build resilient)
    if [ -z "${asn_md5}" ]; then
        asn_md5=$(md5sum "${mmdb_dst_dir}/GeoLite2-ASN.mmdb" | awk '{print $1}')
    fi
    if [ -z "${city_md5}" ]; then
        city_md5=$(md5sum "${mmdb_dst_dir}/GeoLite2-City.mmdb" | awk '{print $1}')
    fi
    if [ -z "${generated_at}" ]; then
        generated_at=$(stat -c %Y "${mmdb_dst_dir}/GeoLite2-City.mmdb" 2>/dev/null || echo 0)
    fi

    # Seed store doc with RELATIVE paths (package root expected as CWD)
    cat > "${store_doc}" << EOF
{
  "city": {
    "path": "data/mmdb/GeoLite2-City.mmdb",
    "hash": "${city_md5}",
    "generated_at": ${generated_at}
  },
  "asn": {
    "path": "data/mmdb/GeoLite2-ASN.mmdb",
    "hash": "${asn_md5}",
    "generated_at": ${generated_at}
  }
}
EOF

    chmod 0640 "${store_doc}" || true
    return 0
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
        -e JOBS="${JOBS}" \
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
        ${TEMP_DIR}/data/store/schema \
        ${TEMP_DIR}/data/store/schema/engine-schema \
        ${TEMP_DIR}/data/store/schema/wazuh-logpar-overrides \
        ${TEMP_DIR}/data/store/schema/allowed-fields \
        ${TEMP_DIR}/data/store/geo/mmdb \
        ${TEMP_DIR}/data/kvdb \
        ${TEMP_DIR}/data/tzdb \
        ${TEMP_DIR}/data/mmdb \
        ${TEMP_DIR}/schemas \
        ${TEMP_DIR}/logs \
        ${TEMP_DIR}/sockets

    # Create .keep files
    touch ${TEMP_DIR}/bin/lib/.keep
    touch ${TEMP_DIR}/data/kvdb/.keep
    touch ${TEMP_DIR}/data/tzdb/.keep
    touch ${TEMP_DIR}/data/mmdb/.keep
    touch ${TEMP_DIR}/logs/.keep
    touch ${TEMP_DIR}/sockets/.keep

    # Copy schemas
    cp -r ${WAZUH_PATH}/src/engine/ruleset/schemas/engine-schema.json ${TEMP_DIR}/data/store/schema/engine-schema/0
    cp -r ${WAZUH_PATH}/src/engine/ruleset/schemas/wazuh-logpar-overrides.json ${TEMP_DIR}/data/store/schema/wazuh-logpar-overrides/0
    cp -r ${WAZUH_PATH}/src/engine/ruleset/schemas/allowed-fields.json ${TEMP_DIR}/data/store/schema/allowed-fields/0
    cp -r ${WAZUH_PATH}/src/engine/ruleset/schemas/wazuh-decoders.json ${TEMP_DIR}/schemas/
    cp -r ${WAZUH_PATH}/src/engine/ruleset/schemas/wazuh-filters.json ${TEMP_DIR}/schemas/

    # Copy geo dbs
    install_geoip "${WAZUH_PATH}" "${TEMP_DIR}"

    # Copy scripts and README
    cp -r ${WAZUH_PATH}/src/engine/standalone/run_engine.sh ${TEMP_DIR}/
    chmod +x ${TEMP_DIR}/run_engine.sh
    cp ${WAZUH_PATH}/src/engine/standalone/README.md ${TEMP_DIR}/

    # Copy libraries and binaries
    cp ${WAZUH_PATH}/src/external/rocksdb/build/librocksdb.so.8 ${TEMP_DIR}/bin/lib
    cp ${WAZUH_PATH}/src/libwazuhext.so ${TEMP_DIR}/bin/lib
    cp ${WAZUH_PATH}/src/build/lib/libindexer_connector.so ${TEMP_DIR}/bin/lib
    cp ${WAZUH_PATH}/src/build/lib/libcontent_manager.so ${TEMP_DIR}/bin/lib
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
    echo "    -a, --architecture <arch>  [Optional] Target architecture of the package [amd64/x86_64/arm64/aarch64]. By default: amd64."
    echo "    -j, --jobs <number>        [Optional] Number of parallel jobs when compiling. By default: 2."
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
