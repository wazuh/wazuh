#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# pr-clang.sh — Format all .cpp/.hpp files changed in the current PR
#               (or vs inferred base branch if no PR is associated) under src/.
#
# Usage:
#   ./pr-clang.sh [--check]   # --check: only verify, don't modify (exit 1 if diff)
#   ./pr-clang.sh             # format in-place
# ------------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WAZUH_REPO="${WAZUH_REPO:-$(cd "$SCRIPT_DIR/../../../../.." && pwd)}"
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

DEFAULT_BASE_BRANCH="$(git -C "$WAZUH_REPO" symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null | sed 's@^origin/@@' || true)"
DEFAULT_BASE_BRANCH="${DEFAULT_BASE_BRANCH:-main}"

detect_base_branch() {
  local repo="$1"
  local current_branch upstream_branch candidate ref best_ref
  local mb best_distance distance candidate_divergence best_divergence

  current_branch="$(git -C "$repo" branch --show-current 2>/dev/null || true)"
  upstream_branch="$(git -C "$repo" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"

  # If upstream is not the same feature branch, it is usually the intended diff base.
  if [[ -n "$upstream_branch" && -n "$current_branch" && "$upstream_branch" != "origin/${current_branch}" ]]; then
    echo "${upstream_branch#origin/}"
    return 0
  fi

  best_ref=""
  best_distance=""
  best_divergence=""

  while IFS= read -r ref; do
    [[ -z "$ref" ]] && continue
    [[ "$ref" == "origin/HEAD" ]] && continue
    [[ -n "$current_branch" && "$ref" == "origin/${current_branch}" ]] && continue

    candidate="${ref#origin/}"
    mb="$(git -C "$repo" merge-base HEAD "refs/remotes/origin/${candidate}" 2>/dev/null || true)"
    [[ -z "$mb" ]] && continue

    distance="$(git -C "$repo" rev-list --count "${mb}..HEAD" 2>/dev/null || true)"
    candidate_divergence="$(git -C "$repo" rev-list --count "${mb}..refs/remotes/origin/${candidate}" 2>/dev/null || true)"
    [[ -z "$distance" || -z "$candidate_divergence" ]] && continue

    if [[ -z "$best_ref" ]] || [[ "$distance" -lt "$best_distance" ]] || { [[ "$distance" -eq "$best_distance" ]] && [[ "$candidate_divergence" -lt "$best_divergence" ]]; }; then
      best_ref="$candidate"
      best_distance="$distance"
      best_divergence="$candidate_divergence"
    fi
  done < <(git -C "$repo" for-each-ref --format='%(refname:short)' refs/remotes/origin)

  if [[ -n "$best_ref" ]]; then
    echo "$best_ref"
  else
    echo "$DEFAULT_BASE_BRANCH"
  fi
}

# ------------------------------------------------------------------------------
# Collect changed files: PR/branch commits + staged + untracked
# ------------------------------------------------------------------------------
echo "==> Resolving changed files..."

PR_NUMBER="$(cd "$WAZUH_REPO" && gh pr view --json number -q '.number' 2>/dev/null || true)"
PR_BASE_REF="$(cd "$WAZUH_REPO" && gh pr view --json baseRefName -q '.baseRefName' 2>/dev/null || true)"

if [[ -n "$PR_NUMBER" ]]; then
  echo "    PR #${PR_NUMBER} detected (base: ${PR_BASE_REF:-unknown})."
  COMMITTED_FILES="$(cd "$WAZUH_REPO" && gh pr diff "$PR_NUMBER" --name-only)"
else
  BASE_BRANCH="$(detect_base_branch "$WAZUH_REPO")"
  echo "    No PR associated, diffing against ${BASE_BRANCH}..."
  COMMITTED_FILES="$(git -C "$WAZUH_REPO" diff --name-only --diff-filter=AM "origin/${BASE_BRANCH}...HEAD")"
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
# Filter: only src/**/*.{cpp,hpp}
# ------------------------------------------------------------------------------
FILTERED_FILES=()
while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  [[ "$file" =~ ^src/.*\.(cpp|hpp)$ ]] || continue
  [[ -f "${WAZUH_REPO}/${file}" ]] || continue
  FILTERED_FILES+=("${WAZUH_REPO}/${file}")
done <<< "$CHANGED_FILES"

if [[ ${#FILTERED_FILES[@]} -eq 0 ]]; then
  echo "==> No .cpp/.hpp files changed under src/. Nothing to do."
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
    if ! "$CLANG_FORMAT" --style=file --dry-run --Werror "$f" 2>/dev/null; then
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
  for f in "${FILTERED_FILES[@]}"; do
    "$CLANG_FORMAT" --style=file -i "$f"
  done
  echo "==> Done. ${#FILTERED_FILES[@]} file(s) formatted."
fi
