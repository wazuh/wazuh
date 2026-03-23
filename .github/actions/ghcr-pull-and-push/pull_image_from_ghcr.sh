#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RETRY_SCRIPT="${SCRIPT_DIR}/../../scripts/run_with_retry.sh"

GITHUB_PUSH_SECRET=$1
GITHUB_USER=$2
DOCKER_IMAGE_NAME=$3
if [ -n "${4:-}" ]; then
    DOCKER_IMAGE_TAG="$4"
else
    exit 1
fi
GITHUB_REPOSITORY="wazuh/wazuh"
GITHUB_OWNER="wazuh"
IMAGE_ID=ghcr.io/${GITHUB_OWNER}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}
IMAGE_ID=$(echo ${IMAGE_ID} | tr '[A-Z]' '[a-z]')

export GITHUB_PUSH_SECRET GITHUB_USER

# Login to GHCR
"${RETRY_SCRIPT}" --attempts 4 --delay 5 --backoff 2 --max-delay 20 --timeout 60 \
    --label "Login to GHCR" -- \
    bash -lc 'printf "%s" "$GITHUB_PUSH_SECRET" | docker login https://ghcr.io -u "$GITHUB_USER" --password-stdin'

# Pull and rename image
"${RETRY_SCRIPT}" --attempts 4 --delay 10 --backoff 2 --max-delay 45 --timeout 900 \
    --label "Pull ${IMAGE_ID}" -- \
    docker pull "${IMAGE_ID}"
docker image tag "ghcr.io/${GITHUB_OWNER}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" "${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}"
