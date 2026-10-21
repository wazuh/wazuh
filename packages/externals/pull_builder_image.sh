#!/bin/bash
#
# Pull the builder image packages/externals/builder-images.json names for <key>,
# tagged with the version of VERSION.json, and tag it <local_name>:<first 12 hex
# of its digest>, the name generate_external.sh and the workflow run it as. The
# tag goes to BUILDER_TAG and the digest to BUILDER_IMAGE in $GITHUB_ENV, which
# the legs record in their toolchain. The digest in the tag keeps runs of other
# branches sharing the Docker daemon from swapping the image.
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

version="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["version"])' "${HERE}/../../VERSION.json")"
image="$(python3 "${HERE}/deps.py" builder-image "$@"):${version}"
printf '%s' "${GHCR_TOKEN:?GHCR_TOKEN is required}" | docker login ghcr.io -u "${GITHUB_ACTOR:?}" --password-stdin
"${RETRY}" --attempts 4 --delay 10 --backoff 2 --max-delay 45 --timeout 900 --label "Pull ${image}" -- \
    docker pull "${image}"
# RepoDigests has one entry per repository the image was pulled from; keep this one's.
digest="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${image}" \
    | grep -m1 "^${image%:*}@sha256:" || true)"
if [[ ! "${digest}" =~ @sha256:([0-9a-f]{64})$ ]]; then
    echo "ERROR: ${image} has no registry digest: ${digest}" >&2
    exit 1
fi
tag="${BASH_REMATCH[1]:0:12}"
docker tag "${image}" "${LOCAL_NAME}:${tag}"
[ -z "${GITHUB_ENV:-}" ] || printf 'BUILDER_TAG=%s\nBUILDER_IMAGE=%s\n' "${tag}" "${digest}" >> "${GITHUB_ENV}"
echo "${LOCAL_NAME}:${tag} = ${image} = ${digest}"
