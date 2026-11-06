#!/usr/bin/env bash
# Builds output/<arch>/libbpf-bootstrap.tar.gz (libbpf.so) from this branch.
# Requires (Ubuntu 24.04): zig, libelf-dev, zlib1g-dev, make, curl, python3.

set -euo pipefail

ZIG_VERSION="0.16.0"
LIBBPF_TAG="v1.7.0"

fail() {
    printf '\033[0;31m%s\033[0m\n' "$1" >&2
    exit 1
}
ok() {
    printf '\033[0;32m%s\033[0m\n' "$1"
}

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

# The release tarball of the inventory entry, checked against its upstream_sha256: a tag can move.
read -r LIBBPF_URL LIBBPF_SHA256 < <(python3 - "${REPO_ROOT}/packages/externals/dependencies.json" "${LIBBPF_TAG}" <<'PY'
import json, sys
entry = next(e for e in json.load(open(sys.argv[1]))["entries"] if e["name"] == "libbpf-bootstrap")
if entry["revision"] != sys.argv[2]:
    sys.exit("libbpf-bootstrap: revision %s in the inventory, LIBBPF_TAG %s" % (entry["revision"], sys.argv[2]))
print(entry["url"].replace("{version}", entry["version"]).replace("{revision}", entry["revision"]), entry["upstream_sha256"])
PY
)
curl -fsSL --retry 3 -o "${TMP}/libbpf.tar.gz" "${LIBBPF_URL}"
[ "$(sha256sum "${TMP}/libbpf.tar.gz" | cut -d' ' -f1)" = "${LIBBPF_SHA256}" ] || fail "sha256 mismatch for ${LIBBPF_URL}"
mkdir -p "${TMP}/libbpf"
tar -xzf "${TMP}/libbpf.tar.gz" -C "${TMP}/libbpf" --strip-components=1
mkdir -p "${TMP}/headers"
cp /usr/include/libelf.h /usr/include/gelf.h /usr/include/zlib.h /usr/include/zconf.h "${TMP}/headers/"

# arch:zig_target
for config in amd64:x86_64-linux-gnu.2.17 aarch64:aarch64-linux-gnu.2.17 \
    arm32:arm-linux-gnueabihf.2.17 i386:x86-linux-gnu.2.17 \
    ppc64le:powerpc64le-linux-gnu.2.19; do
    IFS=":" read -r arch zig_target <<<"${config}"
    ok "==> ${arch}"
    PKG="${TMP}/${arch}/libbpf-bootstrap/build"
    mkdir -p "${PKG}/libbpf" "${TMP}/${arch}/stubs"

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
