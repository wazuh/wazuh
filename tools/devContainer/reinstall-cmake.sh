#!/usr/bin/env bash
#-------------------------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See https://go.microsoft.com/fwlink/?linkid=2090316 for license information.
#-------------------------------------------------------------------------------------------------------------
#
set -e
set -o pipefail

CMAKE_VERSION=${1:-"none"}

if [ "${CMAKE_VERSION}" = "none" ]; then
    echo "No CMake version specified, skipping CMake reinstallation"
    exit 0
fi

# Accept both "3.x.y" and "v3.x.y".
CMAKE_VERSION="${CMAKE_VERSION#v}"

# Cleanup temporary directory and associated files when exiting the script.
cleanup() {
    EXIT_CODE=$?
    set +e
    if [[ -n "${TMP_DIR}" ]]; then
        echo "Executing cleanup of tmp files"
        rm -Rf "${TMP_DIR}"
    fi
    exit $EXIT_CODE
}
trap cleanup EXIT


echo "Installing CMake..."
apt-get -y purge --auto-remove cmake
mkdir -p /opt/cmake

architecture=$(dpkg --print-architecture)
case "${architecture}" in
    arm64)
        ARCH=aarch64 ;;
    amd64)
        ARCH=x86_64 ;;
    *)
        echo "Unsupported architecture ${architecture}."
        exit 1
        ;;
esac

CMAKE_BINARY_NAME="cmake-${CMAKE_VERSION}-linux-${ARCH}.sh"
CMAKE_CHECKSUM_NAME="cmake-${CMAKE_VERSION}-SHA-256.txt"
TMP_DIR=$(mktemp -d -t cmake-XXXXXXXXXX)

echo "${TMP_DIR}"
cd "${TMP_DIR}"

curl -fsSLo "${CMAKE_BINARY_NAME}" --retry 3 --retry-delay 2 \
    "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/${CMAKE_BINARY_NAME}"
curl -fsSLo "${CMAKE_CHECKSUM_NAME}" --retry 3 --retry-delay 2 \
    "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/${CMAKE_CHECKSUM_NAME}"

CHECKSUM_LINE="$(grep "  ${CMAKE_BINARY_NAME}$" "${CMAKE_CHECKSUM_NAME}" || true)"
if [ -z "${CHECKSUM_LINE}" ]; then
    echo "Could not find checksum entry for ${CMAKE_BINARY_NAME} in ${CMAKE_CHECKSUM_NAME}"
    exit 1
fi

printf "%s\n" "${CHECKSUM_LINE}" | sha256sum -c -
sh "${TMP_DIR}/${CMAKE_BINARY_NAME}" --prefix=/opt/cmake --skip-license

ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake
ln -s /opt/cmake/bin/ctest /usr/local/bin/ctest
