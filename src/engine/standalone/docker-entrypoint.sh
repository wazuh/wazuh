#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later

# Wazuh package builder
# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

set -e

# Main script body

echo "Starting Wazuh server build process..."

# Set default value for JOBS if not provided
JOBS="${JOBS:-2}"

build_dir="/build_wazuh"

make -C /workspace/wazuh/src deps TARGET=manager

if [ "${BUILD_TYPE}" = "debug" ]; then
    make -j${JOBS} -C /workspace/wazuh/src TARGET=manager DEBUG="yes"
    echo "Debug build completed with ${JOBS} jobs."
else
    make -j${JOBS} -C /workspace/wazuh/src TARGET=manager
    echo "Release build completed with ${JOBS} jobs."
fi

if [ -d "/opt/gcc-14/lib64" ]; then
    mkdir -p /workspace/wazuh/gcc-libs
    cp /opt/gcc-14/lib64/libstdc++.so.6 /workspace/wazuh/gcc-libs/ 2>/dev/null || true
else
    echo "ERROR: /opt/gcc-14/lib64 not found. Cannot copy libstdc++.so.6"
    exit 1
fi
