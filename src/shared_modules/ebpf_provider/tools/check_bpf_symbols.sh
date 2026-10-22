#!/bin/sh
# Asserts the one invariant rt_file.bpf.o must hold to load on a legacy
# RHEL-family kernel: .text contains exactly one function, rt_walk_dentry.
#
# Why this is a build step and not a code-review item: the thing being asserted
# is a COMPILER DECISION. rt_file.bpf.c marks every helper __always_inline and
# exactly one function noinline, but a different clang, a different -O level or
# a new CI image can still place code differently. When that happens the object
# compiles, installs and silently fails to load on 4.18 only -- a platform no CI
# job load-tests. That is precisely how this went unnoticed before.
#
# The rule: a BPF-to-BPF subprogram on 4.18 must take only scalars, and the one
# function here that does is rt_walk_dentry. Anything else landing in .text is
# an outlined helper whose arguments the verifier will refuse, after which it
# walks into the callee at every call site and exceeds its instruction budget.
#
# Usage: check_bpf_symbols.sh <object> [readelf]

set -eu

OBJ="${1:?usage: check_bpf_symbols.sh <object> [readelf]}"
READELF="${2:-readelf}"

if ! command -v "$READELF" >/dev/null 2>&1; then
    echo "check_bpf_symbols: $READELF not found; skipping the .text symbol check on $OBJ" >&2
    exit 0
fi

# .text's section index, as the symbol table reports it.
text_idx=$("$READELF" -SW "$OBJ" | sed -n 's/^[[:space:]]*\[[[:space:]]*\([0-9]\+\)\][[:space:]]\+\.text[[:space:]].*/\1/p')

if [ -z "$text_idx" ]; then
    # No .text at all means nothing was outlined. That is stricter than the
    # invariant demands, so it passes.
    exit 0
fi

funcs=$("$READELF" -sW "$OBJ" \
        | awk -v idx="$text_idx" '$4 == "FUNC" && $7 == idx { print $8 }' \
        | sort -u)

expected="rt_walk_dentry"

if [ "$funcs" != "$expected" ]; then
    echo "" >&2
    echo "ERROR: $OBJ has the wrong .text contents." >&2
    echo "  expected exactly: $expected" >&2
    echo "  found:            ${funcs:-<none>}" >&2
    echo "" >&2
    echo "  Every helper in bpf/rt_file.bpf.c must be inlined; only rt_walk_dentry" >&2
    echo "  may be a subprogram, and only because all of its arguments are scalars." >&2
    echo "  A helper outlined here takes pointer arguments the 4.18 verifier will" >&2
    echo "  not accept, and the object will fail to load on RHEL 8 / CentOS Stream 8" >&2
    echo "  while continuing to work everywhere else." >&2
    echo "" >&2
    exit 1
fi
