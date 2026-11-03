#!/bin/bash
#
# Wazuh consolidated-dependency smoke build (container-side).
#
# Runs inside a Wazuh package builder image. Populates src/external/ from a
# local pool tree (`deps.py mirror` over the consolidate job's output and the
# published pool) instead of packages.wazuh.com, then builds the agent or the
# manager from source. No package is produced: this only confirms the freshly built
# dependencies link into a working Wazuh build, or, with SOURCES_ONLY=yes, that
# the dependencies still build from their sources/.
#
# Inputs (env vars set by the workflow):
#   BUILD_TARGET         agent | manager
#   ARCHITECTURE_TARGET  amd64 | arm64        (informational, for the log)
#   DEPS_DIR             absolute path to the dir that contains pool/
#   JOBS                 parallel build jobs (defaults to nproc)
#   WAZUH_SRC            working tree (default /wazuh-local-src)
#   WAZUH_VERBOSE        "yes" enables `set -x`
#   SOURCES_ONLY         "yes" runs `make deps EXTERNAL_SRC_ONLY=yes` and
#                        `make build-external` before the product build, so
#                        every dependency is compiled from sources/ first
#   DEBUG                "yes" builds the dependencies and the product as Debug
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

deps_args=()
build_args=()
if [ "${SOURCES_ONLY}" = "yes" ]; then
    deps_args+=(EXTERNAL_SRC_ONLY=yes)
fi
if [ "${DEBUG}" = "yes" ]; then
    deps_args+=(DEBUG=yes)
    build_args+=(DEBUG=yes)
fi

log "BUILD_TARGET=${BUILD_TARGET} MAKE_TARGET=${MAKE_TARGET} ARCH=${ARCHITECTURE_TARGET} JOBS=${JOBS} SOURCES_ONLY=${SOURCES_ONLY:-no} DEBUG=${DEBUG:-no}"
log "pool tree: ${DEPS_DIR}/pool"

# Wipe any stale build/ dir: a CMakeCache.txt from an earlier configure pins
# absolute paths and breaks the next configure step.
rm -rf "${SRC_DIR}/build"

if [ "${SOURCES_ONLY}" = "yes" ]; then
    # The builder images lack what some dependencies need to build from source;
    # build_external.sh installs and sets the same before the legs build.
    YUM_TOOLS="zip unzip clang elfutils-libelf-devel pkgconfig perl-IPC-Cmd perl-Time-Piece expat-devel"
    if command -v yum >/dev/null 2>&1; then
        log "installing the build tooling of the legs via yum"
        for _pkg in ${YUM_TOOLS}; do
            yum install -y "${_pkg}" >/dev/null 2>&1 || yum install -y "${_pkg}" || \
                err "yum install ${_pkg} failed; the dependency build may fail"
        done
    fi
    # dbus: centos:6's expat-devel ships without expat.pc.
    if [ -f /usr/include/expat.h ] && ! pkg-config --exists expat 2>/dev/null; then
        export EXPAT_CFLAGS="-I/usr/include"
        export EXPAT_LIBS="-lexpat"
    fi
    # audit-userspace builds its gen_tables helpers with CC_FOR_BUILD, which
    # older autoconf (centos:6) leaves empty in native builds.
    export CC_FOR_BUILD="${CC:-gcc}"
    export CXX_FOR_BUILD="${CXX:-g++}"
fi

log "running 'make deps' against the local pool tree"
make -C "${SRC_DIR}" deps TARGET="${MAKE_TARGET}" DEPS_POOL_URL="file://${DEPS_DIR}/pool" "${deps_args[@]}"

if [ "${SOURCES_ONLY}" = "yes" ]; then
    # The product build cannot compile its dependencies in the same pass: the
    # engine imports abseil by checking at configure time for a directory that
    # only exists once abseil is built, and data_provider's services module
    # does not wait for dbus. The callers grep this phase alone for
    # "Using precompiled"; the product build reuses what it built.
    log "building the dependencies of '${MAKE_TARGET}' from sources"
    set +e
    make -j"${JOBS}" -C "${SRC_DIR}" build-external TARGET="${MAKE_TARGET}" "${build_args[@]}"
    deps_rc=$?
    set -e
    if [ "${deps_rc}" -ne 0 ]; then
        err "build of the dependencies of '${MAKE_TARGET}' failed (make exit ${deps_rc})"
        exit "${deps_rc}"
    fi
fi

log "building '${MAKE_TARGET}' from source"
# Don't abort on failure here: returning the rc at the end keeps the captured
# log complete (errors near the end included) for a human to read, and lets
# the caller's analysis step still run.
set +e
make -j"${JOBS}" -C "${SRC_DIR}" TARGET="${MAKE_TARGET}" "${build_args[@]}"
build_rc=$?
set -e

if [ "${build_rc}" -ne 0 ]; then
    err "build of '${MAKE_TARGET}' failed (make exit ${build_rc})"
else
    log "build of '${MAKE_TARGET}' succeeded"
fi

exit "${build_rc}"
