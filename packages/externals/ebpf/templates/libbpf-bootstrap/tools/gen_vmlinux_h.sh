#/bin/sh

$(dirname "$0")/bpftool btf dump file ${1:-/sys/kernel/btf/vmlinux} format c
