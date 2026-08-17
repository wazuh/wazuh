#!/usr/bin/env bash
# Wazuh agent HTTPS client — Docker demo runner (host side).
# Copyright (C) 2015, Wazuh Inc.
#
# Stages a minimal build context (the module sources + a few header-only deps),
# builds the demo image, and runs it. No prior Wazuh build required; the module
# is compiled inside the container against the distro's libcurl + OpenSSL.
#
#   DEMO_SECONDS=60 ./docker-run.sh   keeps the client running for ~60 s after
#                                     the scripted walkthrough (Ctrl-C stops it
#                                     cleanly at any point).
#
# Needs: docker.
set -euo pipefail
cd "$(dirname "$0")"

MODULE=".."                                   # the https_client dir
SRC_ROOT="$(cd ../../.. && pwd)"              # .../src
IMAGE="wazuh-https-client-demo"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "== staging build context =="
mkdir -p "$STAGE/https_client/demo" "$STAGE/deps/external/nlohmann"
cp -R "$MODULE/include" "$MODULE/src" "$STAGE/https_client/"
cp demo_driver.c mock_manager.py docker-entrypoint.sh "$STAGE/https_client/demo/"
cp "$SRC_ROOT/shared_modules/common/commonDefs.h"  "$STAGE/deps/"
cp "$SRC_ROOT/shared_modules/utils/loggerHelper.h" "$STAGE/deps/"
cp "$SRC_ROOT/external/cJSON/cJSON.h"              "$STAGE/deps/"
cp "$SRC_ROOT/external/nlohmann/json.hpp"          "$STAGE/deps/external/nlohmann/"
cp Dockerfile "$STAGE/"

echo "== building image ${IMAGE} =="
docker build -t "$IMAGE" "$STAGE"

echo "== running the demo in a container =="
docker run --rm --init -e DEMO_SECONDS="${DEMO_SECONDS:-0}" "$IMAGE"
