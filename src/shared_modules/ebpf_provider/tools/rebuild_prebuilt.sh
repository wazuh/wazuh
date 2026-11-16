#!/usr/bin/env bash
# Regenerates the committed prebuilt/<arch>/rt_file.bpf.o objects and everything
# that must land in the same change, as prebuilt/README.md describes.
#
# Run this BEFORE building an agent package whenever bpf/rt_file.bpf.c or
# include/rt_event_contract.h changed. The packaging pipeline cannot do it:
# packages/generate_package.sh builds inside centos:6/debian:7, which have no
# clang new enough for CO-RE, and CMakeLists.txt prefers the committed prebuilt
# over compiling in any case. A stale object is a hard configure-time error
# (RT_BPF_STRICT_PREBUILT, on by default, everywhere).
#
# What it does, per architecture asked for:
#   1. obtains that architecture's vmlinux.h (a file you supply, or an ssh dump)
#   2. compiles prebuilt/<arch>/rt_file.bpf.o
#   3. runs tools/check_bpf_symbols.sh with RT_BPF_SYMBOLS_REQUIRED=1
#   4. rewrites BOTH architectures' .sources.sha256 -- they record the same two
#      source hashes, so refreshing only one leaves the other build failing
#   5. rewrites that architecture's .provenance, keeping any existing notes=
# then, once every requested architecture is built:
#   6. updates the rt_file.bpf.o size in .github/actions/check_files/*.csv
#   7. optionally load-verifies the object for THIS host's architecture
#
# The vendored external/libbpf-bootstrap/vmlinux.h/include/<arch> header CANNOT
# be used: it defines no struct cgroup, css_set or cgroup_subsys_state, and its
# task_struct has no cgroups member, so rt_file.bpf.c has never compiled against
# it. A real host's BTF dump is the only source. Prefer a recent kernel's: CO-RE
# resolves offsets against the running kernel, so newer is the portable
# direction, and a header older than the code needs can fail to compile.
#
# Everything it writes is tracked by git, so `git checkout -- prebuilt
# ../../../.github/actions/check_files` undoes a run.
#
# Usage:
#   tools/rebuild_prebuilt.sh --header x86=ubuntu@buildhost --load-verify
#   tools/rebuild_prebuilt.sh --header x86=/tmp/x86-vmlinux.h --btf x86='6.17 kernel BTF dump (Ubuntu 24.04, 6.17.0-35-generic)'
#   tools/rebuild_prebuilt.sh --header x86=u@h1 --header arm64=u@h2 --notes 'rebuilt for <change>'
#
# Options:
#   --header <arch>=<path|ssh-target>  required, repeatable; arch is x86 or arm64
#   --btf <arch>=<description>         required when that arch's header is a file
#   --notes <text>                     notes= line written to every provenance
#   --clang <binary>                   default: clang
#   --no-manifests                     leave the check_files CSVs alone
#   --load-verify                      bpftool prog loadall the local arch's object (needs root)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDER="$(cd "${HERE}/.." && pwd)"
REPO="$(cd "${PROVIDER}/../../.." && pwd)"
CHECK_FILES="${REPO}/.github/actions/check_files"

CLANG="clang"
NOTES=""
DO_MANIFESTS=1
DO_LOAD_VERIFY=0
EXPECT_PROGS="${RT_EXPECT_PROGS:-14}"
declare -A HEADER=()
declare -A BTF=()

die() { echo "ERROR: $*" >&2; exit 1; }

arch_ok() { [ "$1" = "x86" ] || [ "$1" = "arm64" ]; }

while [ $# -gt 0 ]; do
    case "$1" in
        --header)
            a="${2%%=*}"; v="${2#*=}"
            arch_ok "$a" || die "unknown architecture '$a'; use x86 or arm64"
            [ "$v" != "$2" ] || die "--header wants <arch>=<path|ssh-target>, got '$2'"
            HEADER[$a]="$v"; shift 2 ;;
        --btf)
            a="${2%%=*}"; v="${2#*=}"
            arch_ok "$a" || die "unknown architecture '$a'; use x86 or arm64"
            [ "$v" != "$2" ] || die "--btf wants <arch>=<description>, got '$2'"
            BTF[$a]="$v"; shift 2 ;;
        --notes) NOTES="$2"; shift 2 ;;
        --clang) CLANG="$2"; shift 2 ;;
        --no-manifests) DO_MANIFESTS=0; shift ;;
        --load-verify) DO_LOAD_VERIFY=1; shift ;;
        -h|--help) sed -n '2,46p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ "${#HEADER[@]}" -gt 0 ] || die "at least one --header <arch>=<path|ssh-target> is required"
command -v "$CLANG" >/dev/null 2>&1 || die "$CLANG not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"
[ -r "${PROVIDER}/bpf/rt_file.bpf.c" ] || die "no bpf/rt_file.bpf.c under ${PROVIDER}"

# The libbpf headers rt_file.bpf.c includes are a separate package from clang.
# Preprocess rather than compile: bpf_helpers.h needs the __u32/__u64 that
# vmlinux.h supplies, so a syntax check fails even where the header is present.
echo '#include <bpf/bpf_helpers.h>' | "$CLANG" -target bpf -E -x c - >/dev/null 2>&1 \
    || die "libbpf development headers not found (bpf/bpf_helpers.h); install libbpf-dev / libbpf-devel"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Writes $WORK/<arch>/vmlinux.h and sets BTF[$arch] when dumped over ssh.
obtain_header() {
    local arch="$1" src="${HEADER[$1]}" dir="${WORK}/$1"
    mkdir -p "$dir"

    if [ -f "$src" ]; then
        cp "$src" "${dir}/vmlinux.h"
        [ -n "${BTF[$arch]:-}" ] \
            || die "--header ${arch}=${src} is a file, so --btf ${arch}='<description>' is required; the provenance cannot record a kernel it was not told about"
        echo "  ${arch}: header from ${src}"
    else
        command -v ssh >/dev/null 2>&1 || die "ssh not found, and --header ${arch}=${src} is not a readable file"
        echo "  ${arch}: dumping BTF from ${src}"
        ssh "$src" 'bpftool btf dump file /sys/kernel/btf/vmlinux format c' > "${dir}/vmlinux.h" \
            || die "bpftool btf dump failed on ${src}"

        local kver pretty machine
        kver="$(ssh "$src" 'uname -r')"
        machine="$(ssh "$src" 'uname -m')"
        pretty="$(ssh "$src" '. /etc/os-release 2>/dev/null; printf "%s" "${PRETTY_NAME:-unknown}"')"
        BTF[$arch]="${kver%%-*} kernel BTF dump (bpftool btf dump file /sys/kernel/btf/vmlinux format c, ${pretty} ${machine}, ${kver})"
    fi

    # Debian's bpftool is a wrapper that needs linux-tools for the exact running
    # kernel; without it, it prints an installation notice to stdout. Catching
    # that here turns a baffling clang error into a clear one.
    grep -q 'struct task_struct' "${dir}/vmlinux.h" \
        || die "${arch}: ${src} is not a vmlinux.h BTF dump (no struct task_struct in it)"
}

build_arch() {
    local arch="$1" dir="${WORK}/$1"
    local obj="${PROVIDER}/prebuilt/${arch}/rt_file.bpf.o"
    mkdir -p "${PROVIDER}/prebuilt/${arch}"

    echo "==> compiling ${arch}"
    "$CLANG" -O2 -g -target bpf "-D__TARGET_ARCH_${arch}" \
        -I"${PROVIDER}/include" -I"$dir" \
        -c "${PROVIDER}/bpf/rt_file.bpf.c" -o "$obj"

    # The one invariant that decides whether it loads on a 4.18 kernel at all.
    RT_BPF_SYMBOLS_REQUIRED=1 "${HERE}/check_bpf_symbols.sh" "$obj"

    local prov="${obj}.provenance" notes=""
    if [ -n "$NOTES" ]; then
        notes="notes=${NOTES}"
    elif [ -f "$prov" ]; then
        # Keep the existing notes block rather than silently dropping it.
        notes="$(sed -n '/^notes=/,$p' "$prov")"
    fi
    {
        echo "arch=${arch}"
        echo "vmlinux_btf=${BTF[$arch]}"
        echo "clang=$("$CLANG" --version | head -1)"
        echo "load_verified=none (rebuild_prebuilt.sh)"
        if [ -n "$notes" ]; then printf '%s\n' "$notes"; fi
    } > "$prov"

    echo "    $(stat -c%s "$obj") bytes"
}

# Both digests, always: each arch directory records the same two source hashes,
# so refreshing only the arch just built leaves the other one failing the gate.
refresh_digests() {
    local c h a
    c="$(sha256sum "${PROVIDER}/bpf/rt_file.bpf.c" | cut -d' ' -f1)"
    h="$(sha256sum "${PROVIDER}/include/rt_event_contract.h" | cut -d' ' -f1)"
    for a in x86 arm64; do
        [ -d "${PROVIDER}/prebuilt/${a}" ] || continue
        printf '%s %s\n' "$c" "$h" > "${PROVIDER}/prebuilt/${a}/rt_file.bpf.o.sources.sha256"
        echo "    ${a}/rt_file.bpf.o.sources.sha256"
    done
}

# check_files rows carry the object's real size with a 0.1 tolerance, which
# absorbs a recompile but not a size change from edited source. A listed file
# the build did not produce, or a produced file no row lists, both fail the
# checker, so a missing row is reported rather than added blind.
update_manifests() {
    local arch="$1" size suffix csv tmp
    size="$(stat -c%s "${PROVIDER}/prebuilt/${arch}/rt_file.bpf.o")"
    suffix=$([ "$arch" = "x86" ] && echo amd64 || echo arm64)

    for csv in "${CHECK_FILES}"/deb_linux_agent_${suffix}.csv "${CHECK_FILES}"/rpm_linux_agent_${suffix}.csv; do
        if [ ! -f "$csv" ]; then
            echo "    WARNING: no such manifest: ${csv}" >&2
            continue
        fi
        if ! grep -q '^/var/ossec/lib/rt_file\.bpf\.o,' "$csv"; then
            echo "    WARNING: $(basename "$csv") has no rt_file.bpf.o row; add one or check_files will fail" >&2
            continue
        fi
        tmp="${WORK}/$(basename "$csv")"
        awk -F, -v OFS=, -v sz="$size" \
            '$1=="/var/ossec/lib/rt_file.bpf.o"{$7=sz}1' "$csv" > "$tmp"
        cp "$tmp" "$csv"
        echo "    $(basename "$csv"): size_bytes=${size}"
    done
}

load_verify() {
    local machine arch obj pin n
    machine="$(uname -m)"
    case "$machine" in
        x86_64) arch=x86 ;;
        aarch64) arch=arm64 ;;
        *) echo "    skipping: no prebuilt directory for $machine" >&2; return 0 ;;
    esac
    if [ -z "${HEADER[$arch]:-}" ]; then
        echo "    skipping: ${arch} was not rebuilt by this run" >&2
        return 0
    fi
    [ "$(id -u)" = "0" ] || die "--load-verify needs root"
    command -v bpftool >/dev/null 2>&1 || die "bpftool not found"

    obj="${PROVIDER}/prebuilt/${arch}/rt_file.bpf.o"
    pin="/sys/fs/bpf/rt_file_verify"
    [ -e "$pin" ] && die "${pin} already exists; remove it yourself so this does not unpin something else"

    bpftool prog loadall "$obj" "$pin" || die "bpftool prog loadall failed on ${obj}"
    n="$(find "$pin" -type f | wc -l)"
    rm -rf -- "$pin"

    echo "    loaded on $(uname -r), ${n} program(s) pinned"
    [ "$n" = "$EXPECT_PROGS" ] \
        || echo "    WARNING: expected ${EXPECT_PROGS} programs, got ${n}; set RT_EXPECT_PROGS if the object legitimately changed" >&2

    sed -i "s|^load_verified=.*|load_verified=bpftool prog loadall, $(uname -sm) $(uname -r), ${n} programs pinned|" \
        "${obj}.provenance"
}

echo "==> headers"
for arch in "${!HEADER[@]}"; do
    obtain_header "$arch"
done

for arch in "${!HEADER[@]}"; do
    build_arch "$arch"
done

echo "==> digests"
refresh_digests

if [ "$DO_MANIFESTS" -eq 1 ]; then
    echo "==> check_files manifests"
    for arch in "${!HEADER[@]}"; do
        update_manifests "$arch"
    done
fi

if [ "$DO_LOAD_VERIFY" -eq 1 ]; then
    echo "==> load verification"
    load_verify
fi

echo
echo "Done. Review the diff before committing:"
echo "  git -C ${REPO} status --short src/shared_modules/ebpf_provider/prebuilt .github/actions/check_files"
if [ "${#HEADER[@]}" -lt 2 ]; then
    echo
    echo "Only one architecture was rebuilt. The other prebuilt object is now older"
    echo "than its refreshed digest claims; rebuild it before the branch is merged."
fi
