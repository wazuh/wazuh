#!/usr/bin/env bash
# Builds output/<arch>/libbpf-bootstrap.tar.gz (modern.bpf.o + libbpf.so) from this branch.
# Requires (Ubuntu 24.04): clang-20 from apt.llvm.org, zig, libelf-dev, zlib1g-dev, git, make.

set -euo pipefail

CLANG_VERSION="20.1.8"
ZIG_VERSION="0.16.0"
LIBBPF_TAG="v1.7.0"
VMLINUX_H_COMMIT="c32912840154a82205530cd6d498b346ac73a6d1"

fail() {
    printf '\033[0;31m%s\033[0m\n' "$1" >&2
    exit 1
}
ok() {
    printf '\033[0;32m%s\033[0m\n' "$1"
}

clang-20 --version 2>/dev/null | grep -q "clang version ${CLANG_VERSION}" || fail "clang ${CLANG_VERSION} required"
[ "$(zig version 2>/dev/null)" = "${ZIG_VERSION}" ] || fail "zig ${ZIG_VERSION} required"
for header in libelf.h gelf.h zlib.h zconf.h; do
    [ -f "/usr/include/${header}" ] || fail "/usr/include/${header} is required (libelf-dev, zlib1g-dev)"
done

OUT_DIR="$(pwd)/output"
cd "$(dirname "$0")/../../.."
REPO_ROOT="$(pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
# Keep build paths out of the debug info so the output is reproducible
PREFIX_MAP="-ffile-prefix-map=${TMP}=/build -ffile-prefix-map=${REPO_ROOT}=/wazuh"

git init -q "${TMP}/vmlinux.h"
git -C "${TMP}/vmlinux.h" fetch -q --depth 1 https://github.com/libbpf/vmlinux.h.git "${VMLINUX_H_COMMIT}"
git -C "${TMP}/vmlinux.h" checkout -q FETCH_HEAD
git -c advice.detachedHead=false clone -q --depth 1 --branch "${LIBBPF_TAG}" https://github.com/libbpf/libbpf.git "${TMP}/libbpf"
mkdir -p "${TMP}/libbpf-headers" "${TMP}/headers"
ln -s "${TMP}/libbpf/src" "${TMP}/libbpf-headers/bpf"
cp /usr/include/libelf.h /usr/include/gelf.h /usr/include/zlib.h /usr/include/zconf.h "${TMP}/headers/"

# arch:bpf_arch:zig_target
for config in amd64:x86:x86_64-linux-gnu.2.17 aarch64:arm64:aarch64-linux-gnu.2.17 \
    arm32:arm:arm-linux-gnueabihf.2.17 i386:x86:x86-linux-gnu.2.17 \
    ppc64le:powerpc:powerpc64le-linux-gnu.2.19; do
    IFS=":" read -r arch bpf_arch zig_target <<<"${config}"
    ok "==> ${arch}"
    PKG="${TMP}/${arch}/libbpf-bootstrap/build"
    mkdir -p "${PKG}/libbpf" "${TMP}/${arch}/stubs"

    clang-20 -g -O2 -target bpf -D__TARGET_ARCH_${bpf_arch} ${PREFIX_MAP} \
        -I"${TMP}/vmlinux.h/include/${bpf_arch}" -I"${TMP}/libbpf-headers" \
        -I"${TMP}/libbpf/include" -I"${TMP}/libbpf/include/uapi" \
        -c "${REPO_ROOT}/src/syscheckd/src/ebpf/src/modern.bpf.c" -o "${PKG}/modern.bpf.o"

    # Empty stubs so libbpf.so links against libelf.so.1 and libz.so.1 of the target
    for lib in elf z; do
        echo "" | zig cc --target="${zig_target}" -shared -x c - -o "${TMP}/${arch}/stubs/lib${lib}.so" -Wl,-soname,lib${lib}.so.1
    done
    make -s -C "${TMP}/libbpf/src" HOSTARCH="${arch}" clean
    make -s -j"$(nproc)" -C "${TMP}/libbpf/src" HOSTARCH="${arch}" CC="zig cc --target=${zig_target}" AR="zig ar" NO_PKG_CONFIG=1 \
        EXTRA_CFLAGS="-I${TMP}/headers -Wno-error -g0 ${PREFIX_MAP}" \
        EXTRA_LDFLAGS="-L${TMP}/${arch}/stubs -Wl,--no-as-needed -lelf -lz -Wl,--strip-debug" \
        libbpf.so
    cp -L "${TMP}/libbpf/src/libbpf.so" "${PKG}/libbpf/libbpf.so"

    mkdir -p "${OUT_DIR}/${arch}"
    tar --owner=0 --group=0 --numeric-owner -czf "${OUT_DIR}/${arch}/libbpf-bootstrap.tar.gz" -C "${TMP}/${arch}" libbpf-bootstrap
    ok "${OUT_DIR}/${arch}/libbpf-bootstrap.tar.gz"
done
