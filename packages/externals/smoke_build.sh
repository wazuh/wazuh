#!/bin/bash
#
# Wazuh consolidated-dependency smoke build (container-side).
#
# Runs inside a Wazuh package builder image. Populates src/external/ from a
# local pool tree (`deps.py mirror` over the consolidate job's output and the
# published pool) instead of packages.wazuh.com, then builds the agent or the
# manager from source. No package is produced — this only confirms the freshly built
# dependencies link into a working Wazuh build.
#
# Inputs (env vars set by the workflow):
#   BUILD_TARGET         agent | manager
#   ARCHITECTURE_TARGET  amd64 | arm64        (informational, for the log)
#   DEPS_DIR             absolute path to the dir that contains pool/
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
DEPS_DIR="${DEPS_DIR:?DEPS_DIR is required (path containing pool/)}"
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
# the host-side tools shipped in <ref>/windows/<dep>.tar.gz (notably
# flatbuffers' `flatc`, which `make TARGET=winagent` invokes during schema
# codegen) get exercised against the same glibc/libstdc++ the downstream
# windows agent build sees.
case "${BUILD_TARGET}" in
    agent)    MAKE_TARGET="agent" ;;
    manager)  MAKE_TARGET="server" ;;
    winagent) MAKE_TARGET="winagent" ;;
    *)        err "BUILD_TARGET must be 'agent', 'manager' or 'winagent' (got '${BUILD_TARGET}')"; exit 2 ;;
esac

if [ ! -d "${DEPS_DIR}/pool" ]; then
    err "no pool/ tree under ${DEPS_DIR}; build it with deps.py mirror"
    exit 2
fi

log "BUILD_TARGET=${BUILD_TARGET} MAKE_TARGET=${MAKE_TARGET} ARCH=${ARCHITECTURE_TARGET} JOBS=${JOBS}"
log "pool tree: ${DEPS_DIR}/pool"

# Wipe any stale build/ dir: a CMakeCache.txt from an earlier configure pins
# absolute paths and breaks the next configure step.
rm -rf "${SRC_DIR}/build"

log "running 'make deps' against the local pool tree"
make -C "${SRC_DIR}" deps TARGET="${MAKE_TARGET}" DEPS_POOL_URL="file://${DEPS_DIR}/pool"

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
