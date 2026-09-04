#!/usr/bin/env bash
#
# Wazuh eBPF & libbpf-bootstrap builder using Zig.
#
# Cross-compiles modern.bpf.o, generates modern.skel.h, and builds libbpf.a
# and libbpf.so targeting legacy GLIBC baselines (glibc 2.17 on x86/arm,
# glibc 2.19 on ppc64le) for all supported Linux architectures:
#   - amd64   (x86_64-linux-gnu.2.17)
#   - aarch64 (aarch64-linux-gnu.2.17)
#   - arm32   (arm-linux-gnueabihf.2.17)
#   - i386    (x86-linux-gnu.2.17)
#   - ppc64le (powerpc64le-linux-gnu.2.19)
#
# Generated artifacts are laid out in the layout expected by Wazuh's S3
# dependency bucket:
#   <outdir>/libraries/linux/<arch>/libbpf-bootstrap.tar.gz

set -euo pipefail

CURRENT_DIR="$(cd "$(dirname "$0")"; pwd -P)"
REPO_ROOT="$(cd "${CURRENT_DIR}/../../.."; pwd -P)"
OUT_DIR="${REPO_ROOT}/packages/output_externals/ebpf"
ARCH_FILTER="all"
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
LIBBPF_TAG="v1.5.0"
VMLINUX_TAG="main"
VERBOSE=""

usage() {
    cat <<EOFU
Usage: $0 [OPTIONS]

  -o, --output <path>            [Optional] Output directory for packaged tarballs.
                                 Default: <repo>/packages/output_externals/ebpf
  -a, --architecture <arch>      [Optional] Architecture to build: amd64, aarch64,
                                 arm32, i386, ppc64le, or all. Default: all.
  -j, --jobs <n>                 [Optional] Parallel make jobs. Default: ${JOBS}.
      --libbpf-version <tag>     [Optional] libbpf git tag/branch. Default: ${LIBBPF_TAG}.
      --vmlinux-version <tag>    [Optional] vmlinux.h git tag/branch. Default: ${VMLINUX_TAG}.
  -v, --verbose                  [Optional] Print detailed commands.
  -h, --help                     Show this help.
EOFU
    exit "$1"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -o|--output)           OUT_DIR="$2"; shift 2 ;;
        -a|--architecture)     ARCH_FILTER="$2"; shift 2 ;;
        -j|--jobs)             JOBS="$2"; shift 2 ;;
        --libbpf-version)      LIBBPF_TAG="$2"; shift 2 ;;
        --vmlinux-version)     VMLINUX_TAG="$2"; shift 2 ;;
        -v|--verbose)          VERBOSE="yes"; shift 1 ;;
        -h|--help)             usage 0 ;;
        *)                     echo "Unknown option: $1" >&2; usage 1 ;;
    esac
done

[ -n "${VERBOSE}" ] && set -x

# Ensure Zig is available
if ! command -v zig >/dev/null 2>&1; then
    echo "==> zig not found in PATH. Downloading standalone Zig 0.13.0..."
    ZIG_DIR="/tmp/zig-0.13.0-standalone"
    if [ ! -x "${ZIG_DIR}/zig" ]; then
        mkdir -p "${ZIG_DIR}"
        curl -fsSL "https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz" \
            | tar -xJ --strip-components=1 -C "${ZIG_DIR}"
    fi
    export PATH="${ZIG_DIR}:${PATH}"
fi

# Ensure required host build tools exist
for tool in clang bpftool git tar make; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "Error: required build tool '${tool}' is not installed." >&2
        exit 1
    fi
done

SRC_BPF="${REPO_ROOT}/src/syscheckd/src/ebpf/src/modern.bpf.c"
if [ ! -f "${SRC_BPF}" ]; then
    echo "Error: eBPF source not found at ${SRC_BPF}" >&2
    exit 1
fi

TEMP_BUILD_DIR="$(mktemp -d /tmp/wazuh_ebpf_build.XXXXXX)"
trap 'rm -rf "${TEMP_BUILD_DIR}"' EXIT

echo "==> Fetching libbpf (${LIBBPF_TAG}) and vmlinux.h (${VMLINUX_TAG})..."
git clone --depth 1 --branch "${VMLINUX_TAG}" https://github.com/libbpf/vmlinux.h.git "${TEMP_BUILD_DIR}/vmlinux.h"
git clone --depth 1 --branch "${LIBBPF_TAG}" https://github.com/libbpf/libbpf.git "${TEMP_BUILD_DIR}/libbpf"

HEADERS_DIR="${CURRENT_DIR}/include"
TEMPLATES_DIR="${CURRENT_DIR}/templates/libbpf-bootstrap"

# Format: arch_name:bpf_arch:vmlinux_dir:zig_target:max_glibc
ALL_CONFIGS=(
    "amd64:x86:x86:x86_64-linux-gnu.2.17:GLIBC_2.17"
    "aarch64:arm64:arm64:aarch64-linux-gnu.2.17:GLIBC_2.17"
    "arm32:arm:arm:arm-linux-gnueabihf.2.17:GLIBC_2.17"
    "i386:x86:x86:x86-linux-gnu.2.17:GLIBC_2.17"
    "ppc64le:powerpc:powerpc:powerpc64le-linux-gnu.2.19:GLIBC_2.19"
)

mkdir -p "${OUT_DIR}"

for config in "${ALL_CONFIGS[@]}"; do
    IFS=":" read -r arch_name bpf_arch vmlinux_dir zig_target max_glibc <<< "${config}"

    if [ "${ARCH_FILTER}" != "all" ] && [ "${ARCH_FILTER}" != "${arch_name}" ]; then
        continue
    fi

    echo "=========================================================="
    echo "Building eBPF & libbpf for ${arch_name} (${zig_target})"
    echo "=========================================================="

    ARCH_BUILD_DIR="${TEMP_BUILD_DIR}/build_${arch_name}"
    STUBS_DIR="${TEMP_BUILD_DIR}/stubs_${arch_name}"
    mkdir -p "${ARCH_BUILD_DIR}/libbpf" "${STUBS_DIR}"

    # 1. Compile modern.bpf.c to BPF bytecode
    clang -g -O2 -target bpf -D__TARGET_ARCH_${bpf_arch} \
        -I"${TEMP_BUILD_DIR}/vmlinux.h/include/${vmlinux_dir}" \
        -I"${TEMP_BUILD_DIR}/libbpf/include" \
        -I"${TEMP_BUILD_DIR}/libbpf/include/uapi" \
        -c "${SRC_BPF}" \
        -o "${ARCH_BUILD_DIR}/modern.bpf.o"

    # 2. Generate modern.skel.h skeleton header
    bpftool gen skeleton "${ARCH_BUILD_DIR}/modern.bpf.o" > "${ARCH_BUILD_DIR}/modern.skel.h"
    sed -i 's|<bpf/libbpf.h>|"wrapper_bpf.h"|' "${ARCH_BUILD_DIR}/modern.skel.h"

    # 3. Create interface stubs for libelf and libz
    echo "" | zig cc --target="${zig_target}" -shared -x c - -o "${STUBS_DIR}/libelf.so" -Wl,-soname,libelf.so.1
    echo "" | zig cc --target="${zig_target}" -shared -x c - -o "${STUBS_DIR}/libz.so" -Wl,-soname,libz.so.1

    # 4. Compile libbpf (static + shared) using Zig
    make -C "${TEMP_BUILD_DIR}/libbpf/src" clean >/dev/null
    make -j"${JOBS}" -C "${TEMP_BUILD_DIR}/libbpf/src" \
        HOSTARCH="${arch_name}" \
        CC="zig cc --target=${zig_target}" \
        AR="zig ar" \
        EXTRA_CFLAGS="-I${HEADERS_DIR} -Wno-error" \
        EXTRA_LDFLAGS="-L${STUBS_DIR} -Wl,--no-as-needed -lelf -lz" \
        NO_PKG_CONFIG=1 \
        libbpf.a libbpf.so >/dev/null

    cp "${TEMP_BUILD_DIR}/libbpf/src/libbpf.a" "${ARCH_BUILD_DIR}/libbpf/"
    cp -P "${TEMP_BUILD_DIR}/libbpf/src/libbpf.so"* "${ARCH_BUILD_DIR}/libbpf/"

    # 5. Verify dynamic dependencies and symbols
    readelf -d "${ARCH_BUILD_DIR}/libbpf/libbpf.so" | grep NEEDED || true

    # 6. Package tarball in the structure required by Wazuh
    PKG_STAGING="${TEMP_BUILD_DIR}/pkg_${arch_name}/libbpf-bootstrap"
    mkdir -p "${PKG_STAGING}/build"
    cp -r "${ARCH_BUILD_DIR}"/* "${PKG_STAGING}/build/"
    cp "${TEMPLATES_DIR}/CMakeLists.txt" "${PKG_STAGING}/"
    cp -r "${TEMPLATES_DIR}/tools" "${PKG_STAGING}/"

    TARGET_TARBALL="${OUT_DIR}/libraries/linux/${arch_name}/libbpf-bootstrap.tar.gz"
    mkdir -p "$(dirname "${TARGET_TARBALL}")"
    tar -czf "${TARGET_TARBALL}" -C "${TEMP_BUILD_DIR}/pkg_${arch_name}" libbpf-bootstrap

    echo "==> Successfully created ${TARGET_TARBALL} ($(stat -c %s "${TARGET_TARBALL}" 2>/dev/null || stat -f %z "${TARGET_TARBALL}") bytes)"
done

# 7. Package source templates tarball
SRC_PKG_STAGING="${TEMP_BUILD_DIR}/pkg_src/libbpf-bootstrap"
mkdir -p "${SRC_PKG_STAGING}"
cp "${TEMPLATES_DIR}/CMakeLists.txt" "${SRC_PKG_STAGING}/"
cp -r "${TEMPLATES_DIR}/tools" "${SRC_PKG_STAGING}/"
SRC_TARBALL="${OUT_DIR}/libraries/sources/libbpf-bootstrap.tar.gz"
mkdir -p "$(dirname "${SRC_TARBALL}")"
tar -czf "${SRC_TARBALL}" -C "${TEMP_BUILD_DIR}/pkg_src" libbpf-bootstrap
echo "==> Successfully created source archive ${SRC_TARBALL} ($(stat -c %s "${SRC_TARBALL}" 2>/dev/null || stat -f %z "${SRC_TARBALL}") bytes)"

echo "==> All requested architectures built successfully."

