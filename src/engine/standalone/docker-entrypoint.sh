#!/bin/bash

# Wazuh package builder
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -e

# Main script body

echo "Starting Wazuh server build process..."

build_dir="/build_wazuh"

make -C /workspace/wazuh/src deps TARGET=server

if [ "${BUILD_TYPE}" = "debug" ]; then
    make -j2 -C /workspace/wazuh/src TARGET=server DEBUG="yes"
else
    make -j2 -C /workspace/wazuh/src TARGET=server
fi

if [ -d "/opt/gcc-14/lib64" ]; then
    mkdir -p /workspace/wazuh/gcc-libs
    cp /opt/gcc-14/lib64/libstdc++.so.6 /workspace/wazuh/gcc-libs/ 2>/dev/null || true
else
    echo "ERROR: /opt/gcc-14/lib64 not found. Cannot copy libstdc++.so.6"
    exit 1
fi
