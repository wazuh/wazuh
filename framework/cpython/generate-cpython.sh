#!/bin/bash
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

output_dir="./output"
wazuh_version=$(jq -r '.version' "$(dirname "${BASH_SOURCE[0]}")/../../VERSION.json")
wazuh_root_dir=$(dirname "${BASH_SOURCE[0]}")/../../

main() {

    parse_args "$@" || exit 1
    pull_builder_image
    run_compilation
}

run_compilation() {

  mkdir -p $output_dir
  docker run \
    --env ARCH="$architecture" \
    -it -v $wazuh_root_dir:/wazuh_host -v $output_dir:/output \
    --entrypoint=bash $image /wazuh_host/framework/cpython/compile.sh $compile_parameters
}

pull_builder_image() {

  current_arch=$(uname -m)
  echo $GHCR_TOKEN | docker login ghcr.io -u $GITHUB_USER --password-stdin
  # Set architecture and image variables
  if [ "$current_arch" = "arm64" ] || [ "$current_arch" = "aarch64" ]; then
      architecture="arm64"
      image="ghcr.io/wazuh/pkg_rpm_manager_builder_arm64:$wazuh_version"
  elif [ "$current_arch" = "amd64" ] || [ "$current_arch" = "x86_64" ]; then
      architecture="x86_64"
      image="ghcr.io/wazuh/pkg_rpm_manager_builder_amd64:$wazuh_version"
  else
      echo "Unsupported architecture ($current_arch)" >&2
      exit 1
  fi
  docker pull $image
}

parse_args() {

  env_file="./config.env"
  if [ -f "$env_file" ]; then
    source $env_file
    echo "Using environment variables from $env_file"
  else
    echo "WARNING: $env_file not found. Proceeding without it."
  fi

  required_vars=(
    "GITHUB_USER"
    "GHCR_TOKEN"
  )

  missing_vars=()

  for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
      missing_vars+=("$var")
    fi
  done

  if [ "${#missing_vars[@]}" -ne 0 ]; then
    echo "Error: the following environment variables are missing:"
    for var in "${missing_vars[@]}"; do
      echo "   - $var"
    done
    exit 1
  fi

  if [ -z "${WAZUH_BRANCH:-}" ]; then
    echo "No Wazuh branch specified. Using local source code (no modifications will be applied to it)."
  else
    echo "Wazuh branch specified: $WAZUH_BRANCH"
    compile_parameters+=" --wazuh-branch $WAZUH_BRANCH"
  fi

  if [ "${BUILD_CPYTHON:-false}" = "true" ]; then
    echo "CPython build enabled."
    compile_parameters+=" --build-cpython"
  fi

  if [ "${BUILD_DEPS:-false}" = "true" ]; then
    echo "Dependencies build enabled."
    compile_parameters+=" --build-deps"
  fi
}

main "$@"
