#!/bin/bash
#
# Pull a builder image by the digest packages/externals/builder-images.json pins
# for it and tag it <local_name>:<first 12 hex of the digest>, the name
# generate_external.sh and the workflow run it as; the tag goes to BUILDER_TAG in
# $GITHUB_ENV. The digest in the tag keeps runs of other branches sharing the
# Docker daemon from swapping the image.
#
#   pull_builder_image.sh <local_name> <key>...
#
# <key>... is the path of the image in builder-images.json, e.g.
# `linux manager amd64` or `windows agent`. GHCR_TOKEN and GITHUB_ACTOR log in to
# ghcr.io.

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "usage: $0 <local_name> <key>..." >&2
    exit 2
fi
LOCAL_NAME="$1"
shift
HERE="$(cd "$(dirname "$0")" && pwd)"
RETRY="${HERE}/../../.github/scripts/run_with_retry.sh"

image="$(python3 "${HERE}/deps.py" builder-image "$@")"
printf '%s' "${GHCR_TOKEN:?GHCR_TOKEN is required}" | docker login ghcr.io -u "${GITHUB_ACTOR:?}" --password-stdin
"${RETRY}" --attempts 4 --delay 10 --backoff 2 --max-delay 45 --timeout 900 --label "Pull ${image}" -- \
    docker pull "${image}"
tag="${image##*@sha256:}"
tag="${tag:0:12}"
docker tag "${image}" "${LOCAL_NAME}:${tag}"
[ -z "${GITHUB_ENV:-}" ] || echo "BUILDER_TAG=${tag}" >> "${GITHUB_ENV}"
echo "${LOCAL_NAME}:${tag} = ${image}"
