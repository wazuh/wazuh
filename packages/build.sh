#!/bin/bash

# Wazuh package builder
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

build_directories() {
  local build_folder=$1
  local wazuh_dir="$2"
  local future="$3"

  mkdir -p "${build_folder}"
  wazuh_version="$(cat wazuh*/src/VERSION| cut -d 'v' -f 2)"

  if [[ "$future" == "yes" ]]; then
    wazuh_version="$(future_version "$build_folder" "$wazuh_dir" $wazuh_version)"
    source_dir="${build_folder}/wazuh-${BUILD_TARGET}-${wazuh_version}"
  else
    package_name="wazuh-${BUILD_TARGET}-${wazuh_version}"
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
  local old_name="wazuh-${BUILD_TARGET}-${base_version}"
  local new_name=wazuh-${BUILD_TARGET}-${version}

  local new_wazuh_dir="${build_folder}/${new_name}"
  cp -R ${wazuh_dir} "$new_wazuh_dir"
  find "$new_wazuh_dir" "${specs_path}" \( -name "*VERSION*" -o -name "*changelog*" \
        -o -name "*.spec" \) -exec sed -i "s/${base_version}/${version}/g" {} \;
  sed -i "s/\$(VERSION)/${major}.${minor}/g" "$new_wazuh_dir/src/Makefile"
  sed -i "s/${base_version}/${version}/g" $new_wazuh_dir/src/init/wazuh-{server,client,local}.sh
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

setup_build_manager(){
    echo "setup_build(sources_dir: $1, specs: $2, build: $3, package: $4, debug: $5)"
    sources_dir="$1"
    specs_path="$2"
    build_dir="$3"
    package_name="$4"
    debug="$5"

    cp -pr ${specs_path}/wazuh-${BUILD_TARGET}/debian ${sources_dir}/debian
    cp -p /tmp/gen_permissions.sh ${sources_dir}

    # Generating directory structure to build the .deb package
    cd ${build_dir}/${BUILD_TARGET} && tar -czf ${package_name}.orig.tar.gz "${package_name}"

    # Configure the package with the different parameters
    sed -i "s:RELEASE:${REVISION}:g" ${sources_dir}/debian/changelog
    sed -i "s:export JOBS=.*:export JOBS=${JOBS}:g" ${sources_dir}/debian/rules
    sed -i "s:export DEBUG_ENABLED=.*:export DEBUG_ENABLED=${debug}:g" ${sources_dir}/debian/rules
    sed -i "s#export PATH=.*#export PATH=/usr/local/gcc-5.5.0/bin:${PATH}#g" ${sources_dir}/debian/rules
    sed -i "s#export LD_LIBRARY_PATH=.*#export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}#g" ${sources_dir}/debian/rules
    sed -i "s:export INSTALLATION_DIR=.*:export INSTALLATION_DIR=${INSTALLATION_PATH}:g" ${sources_dir}/debian/rules
    sed -i "s:DIR=\"/var/ossec\":DIR=\"${INSTALLATION_PATH}\":g" ${sources_dir}/debian/{preinst,postinst,prerm,postrm}

    echo "Listing of ${sources_dir}/debian/rules"
    cat ${sources_dir}/debian/rules
}

get_package_and_checksum_manager(){
    echo "get_package_and_checksum()"

    wazuh_version="$1"
    short_commit_hash="$2"
    base_name="wazuh-${BUILD_TARGET}_${wazuh_version}-${REVISION}"
    symbols_base_name="wazuh-${BUILD_TARGET}-dbg_${wazuh_version}-${REVISION}"

    if [[ "${ARCHITECTURE_TARGET}" == "ppc64le" ]]; then
        deb_file="${base_name}_ppc64el.deb"
        symbols_deb_file="${symbols_base_name}_ppc64el.deb"
    else
        deb_file="${base_name}_${ARCHITECTURE_TARGET}.deb"
        symbols_deb_file="${symbols_base_name}_${ARCHITECTURE_TARGET}.deb"
    fi

    if [[ "${IS_STAGE}" == "no" ]]; then
        deb_file="$(sed "s/\.deb/_${short_commit_hash}&/" <<< "$deb_file")"
        symbols_deb_file="$(sed "s/\.deb/_${short_commit_hash}&/" <<< "$symbols_deb_file")"
    fi

    pkg_path="${build_dir}/${BUILD_TARGET}"
    if [[ "${checksum}" == "yes" ]]; then
        cd ${pkg_path} && sha512sum wazuh-${BUILD_TARGET}*deb > /var/local/wazuh/${deb_file}.sha512
        cd ${pkg_path} && sha512sum ${symbols_deb_file} > /var/local/checksum/${symbols_deb_file}.sha512
    fi

    echo "deb_file: ${deb_file}"
    echo "symbols_deb_file: ${symbols_deb_file}"

    echo "Listing of ${pkg_path}"
    ls ${pkg_path}

    find ${pkg_path} -type f -name "wazuh-${BUILD_TARGET}*deb" -exec mv {} /var/local/wazuh/ \;
}

# Main script body

# Script parameters
export REVISION="$1"
export JOBS="$2"
debug="$3"
checksum="$4"
future="$5"
legacy="$6"
src="$7"

build_dir="/build_wazuh"

source helper_function.sh

set -x

# Download source code if it is not shared from the local host
if [ ! -d "/wazuh-local-src" ] ; then
    curl -sL https://github.com/wazuh/wazuh/tarball/${WAZUH_BRANCH} | tar zx
    short_commit_hash="$(curl -s https://api.github.com/repos/wazuh/wazuh/commits/${WAZUH_BRANCH} \
                          | grep '"sha"' | head -n 1| cut -d '"' -f 4 | cut -c 1-11)"
else
    if [ "${legacy}" = "no" ]; then
      short_commit_hash="$(cd /wazuh-local-src && git rev-parse --short HEAD)"
    else
      # Git package is not available in the CentOS 5 repositories.
      hash_commit=$(cat /wazuh-local-src/.git/$(cat /wazuh-local-src/.git/HEAD|cut -d" " -f2))
      short_commit_hash="$(cut -c 1-11 <<< $hash_commit)"
    fi
fi

# Build directories
source_dir=$(build_directories "$build_dir/${BUILD_TARGET}" "wazuh*" $future)

wazuh_version="$(cat $source_dir/src/VERSION| cut -d 'v' -f 2)"
# TODO: Improve how we handle package_name
# Changing the "-" to "_" between target and version breaks the convention for RPM or DEB packages.
# For now, I added extra code that fixes it.
package_name="wazuh-${BUILD_TARGET}-${wazuh_version}"
specs_path="$(find $source_dir -name SPECS|grep $SYSTEM)"

setup_build_manager "$source_dir" "$specs_path" "$build_dir" "$package_name" "$debug"

set_debug $debug $sources_dir

# Installing build dependencies
cd $sources_dir
build_deps $legacy
build_package $package_name $debug "$short_commit_hash" "$wazuh_version"

# Post-processing
get_package_and_checksum_manager $wazuh_version $short_commit_hash $src