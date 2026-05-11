#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# pr-clang.sh — Format all .cpp/.hpp files changed in the current PR
#               (or vs main if no PR is associated) under src/engine/source/.
#
# Usage:
#   ./pr-clang.sh [--check]   # --check: only verify, don't modify (exit 1 if diff)
#   ./pr-clang.sh             # format in-place
# ------------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WAZUH_REPO="${WAZUH_REPO:-$(cd "$SCRIPT_DIR/../../../../.." && pwd)}"
ENGINE_DIR="${WAZUH_REPO}/src/engine"
CLANG_FORMAT="${CLANG_FORMAT:-clang-format}"
CHECK_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    -h|--help)
      echo "Usage: $0 [--check]"
      echo "  --check   Dry-run: report files that need formatting (exit 1 if any)."
      echo "  (default) Format files in-place."
      exit 0
      ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

command -v "$CLANG_FORMAT" >/dev/null 2>&1 || { echo "ERROR: $CLANG_FORMAT not found in PATH" >&2; exit 1; }
command -v gh >/dev/null 2>&1 || { echo "ERROR: gh (GitHub CLI) not found in PATH" >&2; exit 1; }

# ------------------------------------------------------------------------------
# Collect changed files: PR/branch commits + staged + untracked
# ------------------------------------------------------------------------------
echo "==> Resolving changed files..."

PR_NUMBER="$(gh pr view --json number -q '.number' 2>/dev/null || true)"

if [[ -n "$PR_NUMBER" ]]; then
  echo "    PR #${PR_NUMBER} detected."
  COMMITTED_FILES="$(gh pr diff "$PR_NUMBER" --name-only)"
else
  echo "    No PR associated, diffing against main..."
  COMMITTED_FILES="$(git -C "$WAZUH_REPO" diff --name-only --diff-filter=AM main...HEAD)"
fi

# Staged (index) files — added or modified
STAGED_FILES="$(git -C "$WAZUH_REPO" diff --cached --name-only --diff-filter=AM)"

# Unstaged (working tree) modifications
UNSTAGED_FILES="$(git -C "$WAZUH_REPO" diff --name-only --diff-filter=AM)"

# Untracked files
UNTRACKED_FILES="$(git -C "$WAZUH_REPO" ls-files --others --exclude-standard)"

# Merge all sources, deduplicate
CHANGED_FILES="$(printf '%s\n%s\n%s\n%s' "$COMMITTED_FILES" "$STAGED_FILES" "$UNSTAGED_FILES" "$UNTRACKED_FILES" | sort -u)"

# ------------------------------------------------------------------------------
# Filter: only src/engine/source/**/*.{cpp,hpp}
# ------------------------------------------------------------------------------
FILTERED_FILES=()
while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  [[ "$file" == src/engine/source/*.cpp ]] || [[ "$file" == src/engine/source/*.hpp ]] || continue
  [[ -f "${WAZUH_REPO}/${file}" ]] || continue
  FILTERED_FILES+=("${WAZUH_REPO}/${file}")
done <<< "$CHANGED_FILES"

if [[ ${#FILTERED_FILES[@]} -eq 0 ]]; then
  echo "==> No .cpp/.hpp files changed under src/engine/source/. Nothing to do."
  exit 0
fi

echo "==> Found ${#FILTERED_FILES[@]} file(s) to format:"
for f in "${FILTERED_FILES[@]}"; do
  echo "    - ${f#"${WAZUH_REPO}/"}"
done

# ------------------------------------------------------------------------------
# Run clang-format
# ------------------------------------------------------------------------------
if [[ "$CHECK_ONLY" -eq 1 ]]; then
  echo ""
  echo "==> Checking formatting (dry-run)..."
  NEEDS_FMT=0
  for f in "${FILTERED_FILES[@]}"; do
    if ! "$CLANG_FORMAT" --style=file:"${ENGINE_DIR}/.clang-format" --dry-run --Werror "$f" 2>/dev/null; then
      echo "    NEEDS FORMAT: ${f#"${WAZUH_REPO}/"}"
      NEEDS_FMT=1
    fi
  done
  if [[ "$NEEDS_FMT" -eq 1 ]]; then
    echo ""
    echo "==> Some files need formatting. Run '$0' (without --check) to fix."
    exit 1
  else
    echo "==> All files are properly formatted."
    exit 0
  fi
else
  echo ""
  echo "==> Formatting in-place..."
  "$CLANG_FORMAT" --style=file:"${ENGINE_DIR}/.clang-format" -i "${FILTERED_FILES[@]}"
  echo "==> Done. ${#FILTERED_FILES[@]} file(s) formatted."
fi
