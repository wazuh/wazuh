#!/bin/bash

env_file="./config.env"
current_arch=$(uname -m)
wazuh_version=$(jq -r '.version' ../../VERSION.json)
wazuh_root_dir=$(dirname "${BASH_SOURCE[0]}")/../../

if [ ! -f "$env_file" ]; then
  echo "Error: environment file not found: $env_file" >&2
  exit 1
fi

source $env_file

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

echo $GHCR_TOKEN | docker login ghcr.io -u $GITHUB_USER --password-stdin


if [ "$current_arch" = "arm64" ] || [ "$current_arch" = "aarch64" ]; then
    architecture="arm64"
    docker pull "ghcr.io/wazuh/pkg_rpm_manager_builder_arm64:$wazuh_version"
elif [ "$current_arch" = "amd64" ] || [ "$current_arch" = "x86_64" ]; then
    architecture="x86_64"
    docker pull "ghcr.io/wazuh/pkg_rpm_manager_builder_amd64:$wazuh_version"
else
    echo "Unsupported architecture ($current_arch)" >&2
    exit 1
fi

docker run \
  --env ARCH="$architecture" \
  -it -v $wazuh_root_dir:/wazuh \
  --entrypoint=bash ghcr.io/wazuh/pkg_rpm_manager_builder_$architecture:$wazuh_version /wazuh/framework/cpython/compile.sh --build-cpython --build-deps
