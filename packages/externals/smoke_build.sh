#!/bin/bash
#
# Wazuh consolidated-dependency smoke build (container-side).
#
# Runs inside a Wazuh package builder image. Populates src/external/ from a
# locally-staged consolidated dependency tree (the externals-all artifact
# produced by 5_builderpackage_externals.yml's consolidate job) instead of
# pulling from packages.wazuh.com, then builds the agent or the manager from
# source. No package is produced — this only confirms the freshly built
# dependencies link into a working Wazuh build.
#
# Inputs (env vars set by the workflow):
#   BUILD_TARGET         agent | manager
#   ARCHITECTURE_TARGET  amd64 | arm64        (informational, for the log)
#   DEPS_DIR             absolute path to the dir that contains libraries/
#                        (the extracted externals-all tree)
#   JOBS                 parallel build jobs (defaults to nproc)
#   WAZUH_SRC            working tree (default /wazuh-local-src)
#   WAZUH_VERBOSE        "yes" enables `set -x`
#
# Exit status mirrors the `make` build so the workflow step fails on a
# broken build; the dependency-usage analysis is left to the caller, which
# greps the captured log.

set -e

WAZUH_SRC="${WAZUH_SRC:-/wazuh-local-src}"
SRC_DIR="${WAZUH_SRC}/src"
DEPS_DIR="${DEPS_DIR:?DEPS_DIR is required (path containing libraries/)}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

if [ "${WAZUH_VERBOSE}" = "yes" ]; then
    set -x
fi

log() { echo "[smoke] $*"; }
err() { echo "[smoke][ERROR] $*" >&2; }

# src/Makefile builds the manager under TARGET=server (the `server` target is
# the one that pulls in build_python and the manager-only externals). The
# agent and winagent targets pass through unchanged — winagent is the windows
# cross-compile, and we run this smoke build inside compile_windows_agent so
# the host-side tools shipped in libraries/windows/<dep>.tar.gz (notably
# flatbuffers' `flatc`, which `make TARGET=winagent` invokes during schema
# codegen) get exercised against the same glibc/libstdc++ the downstream
# windows agent build sees.
case "${BUILD_TARGET}" in
    agent)    MAKE_TARGET="agent" ;;
    manager)  MAKE_TARGET="server" ;;
    winagent) MAKE_TARGET="winagent" ;;
    *)        err "BUILD_TARGET must be 'agent', 'manager' or 'winagent' (got '${BUILD_TARGET}')"; exit 2 ;;
esac

if [ ! -d "${DEPS_DIR}/libraries" ]; then
    err "no libraries/ tree under ${DEPS_DIR} — was the externals-all artifact extracted there?"
    exit 2
fi

log "BUILD_TARGET=${BUILD_TARGET} MAKE_TARGET=${MAKE_TARGET} ARCH=${ARCHITECTURE_TARGET} JOBS=${JOBS}"
log "consolidated deps tree: ${DEPS_DIR}/libraries"
ls -la "${DEPS_DIR}/libraries" "${DEPS_DIR}/libraries"/* 2>/dev/null || true

# Wipe any stale build/ dir: a CMakeCache.txt from an earlier configure pins
# absolute paths and breaks the next configure step.
rm -rf "${SRC_DIR}/build"

# Point `make deps` at the local tree instead of packages.wazuh.com.
# RESOURCES_URL is `:=`-assigned in src/Makefile, but a command-line override
# still wins; the deps rules fetch with `curl`, which handles file:// URLs, so
# each <dep>.tar.gz is "downloaded" straight off local disk. Only the external
# dependencies are redirected here — http-request and the indexer templates
# fetch from their own upstreams as usual, which is the real behaviour.
LOCAL_RESOURCES_URL="file://${DEPS_DIR}"

log "running 'make deps' against the consolidated tree (RESOURCES_URL=${LOCAL_RESOURCES_URL})"
make -C "${SRC_DIR}" deps TARGET="${MAKE_TARGET}" RESOURCES_URL="${LOCAL_RESOURCES_URL}"

log "building '${MAKE_TARGET}' from source"
# Don't abort on failure here: returning the rc at the end keeps the captured
# log complete (errors near the end included) for a human to read, and lets
# the caller's analysis step still run.
set +e
make -j"${JOBS}" -C "${SRC_DIR}" TARGET="${MAKE_TARGET}"
build_rc=$?
set -e

if [ "${build_rc}" -ne 0 ]; then
    err "build of '${MAKE_TARGET}' failed (make exit ${build_rc})"
else
    log "build of '${MAKE_TARGET}' succeeded"
fi

exit "${build_rc}"
