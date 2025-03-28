#!/bin/bash

# Wazuh package builder
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
set -e

build_directories() {
  local build_folder=$1
  local wazuh_dir="$2"
  local future="$3"

  mkdir -p "${build_folder}"
  wazuh_version="$(grep '"version"' wazuh*/VERSION.json | sed -E 's/.*"version": *"([^"]+)".*/\1/')"

  if [[ "$future" == "yes" ]]; then
    wazuh_version="$(future_version "$build_folder" "$wazuh_dir" $wazuh_version)"
    source_dir="${build_folder}/wazuh-server-${wazuh_version}"
  else
    package_name="wazuh-server-${wazuh_version}"
    source_dir="${build_folder}/${package_name}"
    cp -R $wazuh_dir "$source_dir"
  fi
  echo "$source_dir"
}

# Function to handle future version
future_version() {
  local build_folder="$1"
  local wazuh_dir="$2"
  local base_version="$3"

  specs_path="$(find $wazuh_dir -name SPECS|grep $SYSTEM)"

  local major=$(echo "$base_version" | cut -dv -f2 | cut -d. -f1)
  local minor=$(echo "$base_version" | cut -d. -f2)
  local version="${major}.30.0"
  local old_name="wazuh-server-${base_version}"
  local new_name=wazuh-server-${version}

  local new_wazuh_dir="${build_folder}/${new_name}"
  cp -R ${wazuh_dir} "$new_wazuh_dir"
  find "$new_wazuh_dir" "${specs_path}" \( -name "*VERSION*" -o -name "*changelog*" \
        -o -name "*.spec" \) -exec sed -i "s/${base_version}/${version}/g" {} \;
  sed -i "s/\$(VERSION)/${major}.${minor}/g" "$new_wazuh_dir/src/Makefile"
  sed -i "s/${base_version}/${version}/g" $new_wazuh_dir/src/init/wazuh-server.sh
  echo "$version"
}

# Function to generate checksum and move files
post_process() {
  local file_path="$1"
  local checksum_flag="$2"
  local source_flag="$3"

  if [[ "$checksum_flag" == "yes" ]]; then
    sha512sum "$file_path" > /var/local/checksum/$(basename "$file_path").sha512
  fi

  if [[ "$source_flag" == "yes" ]]; then
    mv "$file_path" /var/local/wazuh
  fi
}

# Main script body

# Script parameters
export REVISION="$1"
export JOBS="$2"
debug="$3"
checksum="$4"
future="$5"
src="$6"

build_dir="/build_wazuh"

source helper_function.sh

set -x

# Download source code if it is not shared from the local host
if [ ! -d "/wazuh-local-src" ] ; then
    git clone --branch ${WAZUH_BRANCH} --recurse-submodules https://github.com/wazuh/wazuh.git
    cd wazuh
    git submodule update --init --recursive
    short_commit_hash=$(git rev-parse --short HEAD)
    cd ..
else
    short_commit_hash="$(cd /wazuh-local-src && git config --global --add safe.directory /wazuh-local-src && git rev-parse --short HEAD)"
fi

# Build directories
source_dir=$(build_directories "$build_dir/server" "wazuh*" $future)

wazuh_version="$(grep '"version"' $source_dir/VERSION.json | sed -E 's/.*"version": *"([^"]+)".*/\1/')"
# TODO: Improve how we handle package_name
# Changing the "-" to "_" between target and version breaks the convention for RPM or DEB packages.
# For now, I added extra code that fixes it.
package_name="wazuh-server-${wazuh_version}"
specs_path="$(find $source_dir -name SPECS|grep $SYSTEM)"

setup_build "$source_dir" "$specs_path" "$build_dir" "$package_name" "$debug" "$short_commit_hash"

set_debug $debug $sources_dir

# Installing build dependencies
cd $sources_dir
build_deps
build_package $package_name $debug "$short_commit_hash" "$wazuh_version"

# Post-processing
get_package_and_checksum $wazuh_version $short_commit_hash $src
