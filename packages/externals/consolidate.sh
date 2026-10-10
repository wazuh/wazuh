#!/bin/bash
#
# Merge the per-leg externals tarballs and the libbpf-bootstrap build into one
# pool tree, and write the manifest.json of every ref in it.
#
#   consolidate.sh <legs_dir> <ebpf_dir> <out_dir> [<wazuh_commit> <workflow_run>]
#
# <legs_dir>  holds externals-<system>-<arch>-<target>.tar.gz files (at any depth; none when only
#             libbpf-bootstrap changed)
# <ebpf_dir>  holds build_ebpf.sh's <arch>/libbpf-bootstrap.tar.gz (may be missing)
# <out_dir>   gets pool/<name>/<version>-<key>/{sources,<os>/<arch>}/<name>.tar.gz, and toolchain/
#             with the <leg>.txt each leg recorded, which the manifests carry

set -euo pipefail

LEGS_DIR="$1"
EBPF_DIR="$2"
OUT_DIR="$3"
WAZUH_COMMIT="${4:-}"
WORKFLOW_RUN="${5:-}"
REPO="$(cd "$(dirname "$0")/../.."; pwd -P)"
POOL="${OUT_DIR}/pool"

staging="$(mktemp -d)"
trap 'rm -rf "${staging}"' EXIT
TOOLCHAIN="${OUT_DIR}/toolchain"
rm -rf "${POOL}" "${TOOLCHAIN}"
mkdir -p "${POOL}" "${TOOLCHAIN}"

# Sources are the same on every leg, so the first copy is kept. Where two legs
# compiled the same dependency (the Linux agent and manager legs both build the
# agent set), the agent leg's copy is kept: its centos:6 / glibc-2.12 binaries
# link in every Wazuh builder image, the manager's centos:7 ones do not. The
# manager legs are merged first so the agent legs overwrite them.
legs="$( (find "${LEGS_DIR}" -name 'externals-*.tar.gz' 2>/dev/null || true) | sort)"
ebpf="$( (find "${EBPF_DIR}" -path '*/*/libbpf-bootstrap.tar.gz' 2>/dev/null || true) | sort)"
if [ -z "${legs}${ebpf}" ]; then
    echo "consolidate: no externals-*.tar.gz under ${LEGS_DIR} nor libbpf-bootstrap under ${EBPF_DIR}" >&2
    exit 1
fi
# Platform directories this run built: the manifests require them of every entry with binaries.
platforms="$(sed -E 's/.*externals-(deb|rpm)-amd64-.*/linux\/amd64/; s/.*externals-(deb|rpm)-arm64-.*/linux\/aarch64/;
                     s/.*externals-macos-intel64-.*/darwin\/amd64/; s/.*externals-macos-arm64-.*/darwin\/aarch64/;
                     s/.*externals-windows-.*/windows/' <<<"${legs}" | sed '/^$/d' | sort -u | paste -sd, -)"
for leg in $(grep -- '-manager\.tar\.gz$' <<<"${legs}" || true) $(grep -v -- '-manager\.tar\.gz$' <<<"${legs}" || true); do
    dir="${staging}/$(basename "${leg}" .tar.gz)"
    mkdir -p "${dir}"
    tar -xzf "${leg}" -C "${dir}"
    if [ -d "${dir}/toolchain" ]; then
        cp "${dir}/toolchain/"*.txt "${TOOLCHAIN}/" 2>/dev/null || true
    fi
    [ -d "${dir}/pool" ] || continue
    while IFS= read -r file; do
        rel="${file#${dir}/pool/}"
        dst="${POOL}/${rel}"
        case "${rel}" in
            */sources/*) [ -e "${dst}" ] && continue ;;
        esac
        mkdir -p "$(dirname "${dst}")"
        cp "${file}" "${dst}"
    done < <(find "${dir}/pool" -type f -name '*.tar.gz')
done

# build_ebpf.sh writes one tarball per Linux architecture; libbpf-bootstrap has no sources/.
ebpf_ref="$(sed -n 's/^DEP_REF_libbpf-bootstrap := //p' "${REPO}/src/deps.lock.mk")"
while IFS= read -r tarball; do
    [ -n "${tarball}" ] || continue
    arch="$(basename "$(dirname "${tarball}")")"
    mkdir -p "${POOL}/${ebpf_ref}/linux/${arch}"
    cp "${tarball}" "${POOL}/${ebpf_ref}/linux/${arch}/"
done <<<"${ebpf}"

# The eBPF job records its own toolchain next to its tarballs.
ebpf_toolchain="$( (find "${EBPF_DIR}" -name toolchain.txt 2>/dev/null || true) | head -n1)"
[ -z "${ebpf_toolchain}" ] || cp "${ebpf_toolchain}" "${TOOLCHAIN}/build-ebpf.txt"

python3 "${REPO}/packages/externals/deps.py" manifest --pool "${POOL}" --platforms "${platforms}" --toolchain "${TOOLCHAIN}" \
    ${WAZUH_COMMIT:+--wazuh-commit "${WAZUH_COMMIT}"} ${WORKFLOW_RUN:+--workflow-run "${WORKFLOW_RUN}"}

echo "pool refs:"
(cd "${POOL}" && find . -name manifest.json | sed 's|^\./||; s|/manifest.json$||' | sort)
