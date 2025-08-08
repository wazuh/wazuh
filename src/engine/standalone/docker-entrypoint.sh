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

make -j 2 -C /workspace/wazuh/src TARGET=server
