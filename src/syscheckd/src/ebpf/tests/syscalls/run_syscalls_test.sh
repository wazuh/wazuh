#!/usr/bin/env bash
# Runs ebpf_syscalls_test on ext4, xfs, btrfs and tmpfs mounts. Requires root.
# Usage: run_syscalls_test.sh <ebpf_syscalls_test> <libbpf-bootstrap/build dir>

set -euo pipefail

TEST_BIN="$(realpath "$1")"
BPF_BUILD="$(realpath "$2")"
WORK="$(mktemp -d)"
chmod 755 "${WORK}"
trap 'umount "${WORK}"/mnt/* 2>/dev/null; rm -rf "${WORK}"' EXIT

mkdir -p "${WORK}/root/lib" "${WORK}/root/tmp"
cp "${BPF_BUILD}/modern.bpf.o" "${WORK}/root/lib/"

dirs=()
for fs in ext4 xfs btrfs tmpfs; do
    mkdir -p "${WORK}/mnt/${fs}"
    if [ "${fs}" = tmpfs ]; then
        mount -t tmpfs tmpfs "${WORK}/mnt/${fs}"
    else
        truncate -s 300M "${WORK}/${fs}.img"
        # 5.4 LTS feature set, mountable on kernel 5.8
        opts=()
        [ "${fs}" = xfs ] && opts=(-c options=/usr/share/xfsprogs/mkfs/lts_5.4.conf)
        "mkfs.${fs}" -q "${opts[@]}" "${WORK}/${fs}.img" >/dev/null
        mount -o loop "${WORK}/${fs}.img" "${WORK}/mnt/${fs}"
    fi
    dirs+=("${WORK}/mnt/${fs}")
done

LD_LIBRARY_PATH="${BPF_BUILD}/libbpf" "${TEST_BIN}" "${WORK}/root" "${dirs[@]}"
