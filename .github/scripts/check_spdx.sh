#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Check the SPDX license line of the files a change adds or touches.
#
# Usage: check_spdx.sh [<base>]
#   <base>  commit to diff against HEAD; default HEAD^1 (the base side of the
#           merge commit that CI checks out for a pull request).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
base="${1:-HEAD^1}"

# Collect the list first: if git diff fails, the script stops here instead of printing an empty
# "checked 0" summary. T (type change, e.g. a symlink replaced by a file) is checked too.
files="$(mktemp)"
trap 'rm -f "$files"' EXIT
git diff --name-only --diff-filter=ACMRT -z "$base" HEAD > "$files"
python3 .github/scripts/spdx_scope.py check - < "$files"
