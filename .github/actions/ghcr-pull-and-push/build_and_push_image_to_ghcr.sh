#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RETRY_SCRIPT="${SCRIPT_DIR}/../../scripts/run_with_retry.sh"

GITHUB_PUSH_SECRET=$1
GITHUB_USER=$2
DOCKER_IMAGE_NAME=$3
BUILD_CONTEXT=$4
DOCKERFILE_PATH="$BUILD_CONTEXT/Dockerfile"
if [ -n "${5:-}" ]; then
    DOCKER_IMAGE_TAG=$5
else
    exit 1
fi
GITHUB_REPOSITORY="wazuh/wazuh"
GITHUB_OWNER="wazuh"
IMAGE_ID_CACHE=ghcr.io/${GITHUB_OWNER}/${DOCKER_IMAGE_NAME}:latest
IMAGE_ID_CACHE=$(echo ${IMAGE_ID_CACHE} | tr '[A-Z]' '[a-z]')
IMAGE_ID=ghcr.io/${GITHUB_OWNER}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}
IMAGE_ID=$(echo ${IMAGE_ID} | tr '[A-Z]' '[a-z]')

export GITHUB_PUSH_SECRET GITHUB_USER

# Login to GHCR
"${RETRY_SCRIPT}" --attempts 4 --delay 5 --backoff 2 --max-delay 20 --timeout 60 \
    --label "Login to GHCR" -- \
    bash -lc 'printf "%s" "$GITHUB_PUSH_SECRET" | docker login https://ghcr.io -u "$GITHUB_USER" --password-stdin'

# Pull latest image id from cache
echo pull ${IMAGE_ID_CACHE}
cache_args=()
if "${RETRY_SCRIPT}" --attempts 3 --delay 10 --backoff 2 --max-delay 40 --timeout 900 \
    --label "Pull cache image ${IMAGE_ID_CACHE}" -- \
    docker pull "${IMAGE_ID_CACHE}"; then
    cache_args=(--cache-from "${IMAGE_ID_CACHE}")
else
    echo "Cache image ${IMAGE_ID_CACHE} is not available. Continuing without remote cache."
fi

# Build image
echo build --build-arg BUILDKIT_INLINE_CACHE=1 "${cache_args[@]}" -t ${IMAGE_ID} -f ${DOCKERFILE_PATH} ${BUILD_CONTEXT}
"${RETRY_SCRIPT}" --attempts 2 --delay 20 --backoff 2 --max-delay 60 --timeout 5400 \
    --label "Build image ${IMAGE_ID}" -- \
    docker build --build-arg BUILDKIT_INLINE_CACHE=1 "${cache_args[@]}" -t "${IMAGE_ID}" -f "${DOCKERFILE_PATH}" "${BUILD_CONTEXT}"
"${RETRY_SCRIPT}" --attempts 4 --delay 15 --backoff 2 --max-delay 60 --timeout 1800 \
    --label "Push image ${IMAGE_ID}" -- \
    docker push "${IMAGE_ID}"
