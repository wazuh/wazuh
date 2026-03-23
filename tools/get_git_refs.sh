#!/usr/bin/env bash

set -e

# Script to determine Git references (branches and tags) for fallback usage
# Returns multiple references, one per line, in priority order
#
# This script uses three methods:
# 1. Git command (if available) - returns branch and/or tag
# 2. Manual .git directory parsing (if git not available) - returns branch and/or tag
# 3. VERSION.json file (always executed) - returns branch and tag from version

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Show help message
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Determine Git references (branches and tags) for fallback usage.
Returns multiple references, one per line, in priority order.

OPTIONS:
    -h, --help     Show this help message and exit

OUTPUT (one per line, in priority order):
    refs/heads/<branch>    Current branch (from git or .git/HEAD)
    refs/tags/<tag>        Current tag (from git or .git/packed-refs)
    refs/heads/<version>   Branch name from VERSION.json
    refs/tags/v<version>   Tag with 'v' prefix from VERSION.json

METHODS (executed in order):
    1. Git command OR .git directory: Returns current branch and/or tag
       - Method 1 and 2 are mutually exclusive (git command takes precedence)
    2. VERSION.json: Always executed, returns branch and tag based on version
       - Special case: version 5.0.0 also returns refs/heads/main as fallback

EXAMPLES:
    $ $(basename "$0")
    refs/heads/enhancement/32855-checkout-indexer-templates
    refs/heads/5.0.0
    refs/tags/v5.0.0
    refs/heads/main

    $ $(basename "$0")  # On a tagged commit with version 4.14.0
    refs/tags/v4.14.0-rc1
    refs/heads/4.14.0
    refs/tags/v4.14.0

EXIT CODES:
    0    Success (at least one reference found)
    1    Unable to determine any Git reference

EOF
}

# Option 1: Use git command if available
# Outputs both branch and tag if found (one per line)
try_git_command() {
    if ! command -v git >/dev/null 2>&1 || [ ! -d "$REPO_ROOT/.git" ]; then
        return 1
    fi

    local has_output=0

    # Try to get the current branch
    local branch
    branch=$(git -C "$REPO_ROOT" symbolic-ref --short HEAD 2>/dev/null || true)
    if [ -n "$branch" ]; then
        echo "refs/heads/$branch"
        has_output=1
    fi

    # Try to get the tag (even if on a branch)
    local tag
    tag=$(git -C "$REPO_ROOT" describe --exact-match --tags 2>/dev/null || true)
    if [ -n "$tag" ]; then
        echo "refs/tags/$tag"
        has_output=1
    fi

    return $((has_output == 0))
}

# Helper: Get commit hash for a given ref
get_commit_hash() {
    local ref_path="$1"
    local commit_hash=""

    # First try loose ref file
    local ref_file="$REPO_ROOT/.git/$ref_path"
    if [ -f "$ref_file" ]; then
        commit_hash=$(cat "$ref_file")
    elif [ -f "$REPO_ROOT/.git/packed-refs" ]; then
        # Try packed-refs
        commit_hash=$(grep " $ref_path\$" "$REPO_ROOT/.git/packed-refs" | awk '{print $1}' | head -n 1)
    fi

    echo "$commit_hash"
}

# Helper: Find tag for a given commit hash
find_tag_for_commit() {
    local commit_hash="$1"

    # First check loose tag refs in .git/refs/tags/
    if [ -d "$REPO_ROOT/.git/refs/tags" ]; then
        for tag_file in "$REPO_ROOT/.git/refs/tags"/*; do
            if [ -f "$tag_file" ]; then
                local tag_commit
                tag_commit=$(cat "$tag_file")
                if [ "$tag_commit" = "$commit_hash" ]; then
                    local tag_name
                    tag_name=$(basename "$tag_file")
                    echo "refs/tags/$tag_name"
                    return 0
                fi
            fi
        done
    fi

    # Then check packed-refs
    if [ -f "$REPO_ROOT/.git/packed-refs" ]; then
        local tag_ref
        tag_ref=$(grep "^$commit_hash" "$REPO_ROOT/.git/packed-refs" | awk '{print $2}' | grep "^refs/tags/" | head -n 1)
        if [ -n "$tag_ref" ]; then
            echo "$tag_ref"
            return 0
        fi
    fi

    return 1
}

# Option 2: Read .git directory manually
# Outputs both branch and tag if found (one per line)
try_git_directory() {
    if [ ! -d "$REPO_ROOT/.git" ] || [ ! -f "$REPO_ROOT/.git/HEAD" ]; then
        return 1
    fi

    local has_output=0
    local head_content
    head_content=$(cat "$REPO_ROOT/.git/HEAD")
    local commit_hash=""

    # Check if HEAD points to a branch
    if [[ "$head_content" == ref:* ]]; then
        # Extract the ref path (e.g., refs/heads/branch-name)
        local ref_path
        ref_path=$(echo "$head_content" | sed 's/^ref: //')
        echo "$ref_path"
        has_output=1

        # Get the commit hash from the branch ref
        commit_hash=$(get_commit_hash "$ref_path")
    else
        # HEAD contains a commit hash (detached state)
        commit_hash="$head_content"
    fi

    # Search for tags pointing to the commit hash
    if [ -n "$commit_hash" ]; then
        local tag_ref
        tag_ref=$(find_tag_for_commit "$commit_hash")
        if [ -n "$tag_ref" ]; then
            echo "$tag_ref"
            has_output=1
        fi
    fi

    return $((has_output == 0))
}

# Option 3: Use VERSION.json
# Always outputs both branch (without 'v') and tag (with 'v' prefix)
get_version_json_refs() {
    if [ ! -f "$REPO_ROOT/VERSION.json" ]; then
        return 1
    fi

    local version
    version=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$REPO_ROOT/VERSION.json" | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    if [ -n "$version" ]; then
        echo "refs/heads/$version"

        # Special case: for version 5.0.0, also try main branch as fallback
        if [ "$version" = "5.0.0" ]; then
            echo "refs/heads/main"
        fi

        echo "refs/tags/v$version"

        return 0
    fi

    return 1
}

# Main execution
main() {
    # Parse arguments
    if [ $# -gt 0 ]; then
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Error: Unknown option '$1'" >&2
                echo "Use --help for usage information" >&2
                exit 1
                ;;
        esac
    fi

    local has_output=0

    # Try git command OR .git directory (mutually exclusive)
    if command -v git >/dev/null 2>&1 && [ -d "$REPO_ROOT/.git" ]; then
        # Use git command
        if try_git_command; then
            has_output=1
        fi
    elif [ -d "$REPO_ROOT/.git" ]; then
        # Use .git directory parsing
        if try_git_directory; then
            has_output=1
        fi
    fi

    # Always get VERSION.json references
    if get_version_json_refs; then
        has_output=1
    fi

    # If no output was generated
    if [ $has_output -eq 0 ]; then
        echo "Unable to determine Git reference" >&2
        exit 1
    fi

    exit 0
}

main "$@"
