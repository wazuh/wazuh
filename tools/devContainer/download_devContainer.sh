#!/bin/bash

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Keep this script compatible with bash 3.2 and the BSD tools of macOS: edit files with
# sed_inplace, resolve paths with abspath, hex-encode with od, and no bash >= 4 constructs.

# Save current directory
OLD_PWD=$(pwd)
readonly OLD_PWD

# Constants
readonly TMP_DIR="/tmp/wazuh_devContainer_$$"  # Use PID for unique temp dir
readonly REPO_DEV_DIR="tools/devContainer"
readonly REPO_URL="https://github.com/wazuh/wazuh.git"
readonly DEFAULT_BRANCH="5.0.0"

readonly EXCLUDED_FILES=(
    "download_devContainer.sh"
    "README.md"
    # The CI's copy (.github/actions/reinstall_cmake) that lives next to the devContainer
    # config; the image uses .devcontainer/reinstall-cmake.sh, which is still downloaded.
    "reinstall-cmake.sh"
)

readonly EXCLUDE_FOLDERS=(
    "scripts"
    "e2e"
)

# Variables
BRANCH="${DEFAULT_BRANCH}"
DEV_CONTAINER_DESTINATION=""
CLAUDE_PACKAGE=""
DEST_CREATED=0   # 1 while the destination exists but is not complete: removed on failure
IMAGE=""         # <repository>:<major.minor>, computed from the cloned branch
JSON_IMAGE=""    # the "image" line of the cloned devcontainer.json
README_URL=""    # the README of the downloaded branch on GitHub (the download does not copy it)
REGISTRY=""      # registry host of IMAGE (e.g. ghcr.io)
OWNER=""         # first path component of the repository (e.g. wazuh)

# Clean up the temporary directory, and the destination if the script failed half way
cleanup() {
    local rc=$?
    cd "$OLD_PWD" || true
    rm -rf "$TMP_DIR"
    if [ "$rc" -ne 0 ] && [ "$DEST_CREATED" -eq 1 ]; then
        rm -rf "$DEV_CONTAINER_DESTINATION"
    fi
}
trap cleanup EXIT

# Print an error and exit
die() {
    echo "Error: $*" >&2
    if [ -n "$README_URL" ]; then
        echo "       Documentation: $README_URL" >&2
    fi
    exit 1
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $(basename "$0") [-d <destination>] [-b <branch>] [-c <claude.tar.gz>] [-h]

Downloads the devContainer of a branch and pulls its prebuilt image. The image is
<repository>:<major.minor>: the repository comes from the "image" line of the branch's
devcontainer.json and the tag from the branch's VERSION.json (5.0.0 -> 5.0). The
destination is only created after the image has been pulled.

The images under ghcr.io/wazuh are private: if your Docker has no credentials for the
registry, the script offers to log in, either with the GitHub CLI (gh) or with a personal
access token (classic) with the read:packages scope. The token is passed to
'docker login --password-stdin', never on the command line. Without a terminal it does
not ask: log in first (README: "Logging in to ghcr.io").

Options:
    -d    Destination directory for devContainer (default: ./devContainer)
    -b    Git branch to download from (default: ${DEFAULT_BRANCH})
    -c    Claude Code setup exported with the claude-portable skill (claude-portable.sh export);
          it is copied into the devContainer and the command to import it is printed
    -h    Show this help message

Environment:
    WAZUH_DEVCONTAINER_IMAGE    Image repository to use instead of the one in devcontainer.json
                                (e.g. a fork: ghcr.io/<owner>/wazuh-devcontainer); the tag is
                                still <major.minor>. The downloaded devcontainer.json points to it.

Examples:
    $(basename "$0")
    $(basename "$0") -d ~/my-devcontainer
    $(basename "$0") -b 5.0.0 -d /tmp/devcontainer
    $(basename "$0") -d ~/my-devcontainer -c ~/claude-portable.tar.gz
EOF
}

# Absolute path of a file or directory that may not exist yet (no realpath on every system)
abspath() {
    local path=$1
    local resolved dir base

    if command -v realpath > /dev/null 2>&1 && resolved=$(realpath "$path" 2> /dev/null); then
        printf '%s\n' "$resolved"
        return 0
    fi

    case "$path" in
        /*) ;;
        *) path="$OLD_PWD/$path" ;;
    esac
    dir=$(dirname "$path")
    base=$(basename "$path")
    if resolved=$(cd "$dir" 2> /dev/null && pwd -P); then
        case "$base" in
            /|.) printf '%s\n' "$resolved" ;;
            *) printf '%s\n' "${resolved%/}/$base" ;;
        esac
    else
        printf '%s\n' "$path"
    fi
}

# Portable in-place edit (BSD and GNU sed differ on -i): write to a temporary file and move it over the original
sed_inplace() {
    local expression=$1
    local file=$2

    if sed "$expression" "$file" > "$file.tmp"; then
        mv "$file.tmp" "$file"
    else
        rm -f "$file.tmp"
        return 1
    fi
}

# Escape a string for the replacement part of a `s|...|...|` sed expression
sed_escape_replacement() {
    printf '%s' "$1" | sed 's/[&|\\]/\\&/g'
}

# Function to validate prerequisites
check_prerequisites() {
    # Check if docker is installed
    if ! command -v docker &> /dev/null; then
        echo "Error: Docker is not installed. Please install Docker before running this script" >&2
        exit 1
    fi

    # Check if docker is running
    if ! docker info &> /dev/null; then
        echo "Error: Docker is not running. Please start Docker before running this script" >&2
        exit 1
    fi

    # Check if the user is in the docker group (Docker Desktop on macOS has no such group).
    # No grep -q: closing the pipe early would make pipefail report a failure.
    if [ "$(uname -s)" != "Darwin" ] && ! groups | tr ' ' '\n' | grep -x "docker" > /dev/null; then
        echo "Warning: The user is not in the docker group. You may need sudo privileges" >&2
    fi

    # Check if git is installed
    if ! command -v git &> /dev/null; then
        echo "Error: Git is not installed. Please install Git before running this script" >&2
        exit 1
    fi
}

# Function to download the repository
download_repo() {
    echo "Downloading devContainer from branch '${BRANCH}'..."

    # Clone the minimal repository
    rm -rf "$TMP_DIR"
    mkdir -p "$TMP_DIR"
    cd "$TMP_DIR" || exit 1

    if ! git clone --filter=blob:none --branch "${BRANCH}" --no-checkout --depth 1 --sparse "$REPO_URL" . 2>&1; then
        echo "Error: Failed to clone repository. Please check if the branch '${BRANCH}' exists" >&2
        exit 1
    fi

    # sparse-checkout for the specific folders (cone mode also brings the root files, e.g. VERSION.json)
    git sparse-checkout init --cone
    git sparse-checkout set "$REPO_DEV_DIR"
    git checkout "${BRANCH}"

    cd "$OLD_PWD" || exit 1
}

# Function to check, before the registry access and the pull, that the branch ships a prebuilt-image devContainer
check_branch_files() {
    local json_file="$TMP_DIR/$REPO_DEV_DIR/.devcontainer/devcontainer.json"

    if [ ! -f "$json_file" ]; then
        echo "Error: no .devcontainer/devcontainer.json under '$REPO_DEV_DIR' on branch '$BRANCH'." >&2
        echo "       Pick a branch that ships the devContainer (e.g. -b 5.0.0)." >&2
        exit 1
    fi

    if [ -z "$(read_json_image "$json_file")" ]; then
        die "branch '$BRANCH' predates the prebuilt devContainer image (no \"image\" line in devcontainer.json). Pick a branch that ships it (README: \"How the image is published\")."
    fi

    if [ ! -f "$TMP_DIR/VERSION.json" ]; then
        die "no VERSION.json on branch '$BRANCH'."
    fi
}

# Print the value of the first "image" line of a devcontainer.json (empty if there is none)
read_json_image() {
    sed -n 's/^[[:space:]]*"image":[[:space:]]*"\([^"]*\)".*$/\1/p' "$1" | sed -n '1p'
}

# Function to compute IMAGE, REGISTRY and OWNER from the cloned branch
compute_image() {
    local json_image repo tag version first rest

    json_image=$(read_json_image "$TMP_DIR/$REPO_DEV_DIR/.devcontainer/devcontainer.json")
    JSON_IMAGE="$json_image"

    # Same rule as build-image.sh: the tag is what follows the last ':' only if it contains no '/'
    # (a registry port is not a tag).
    repo="$json_image"
    case "${json_image##*:}" in
        "$json_image"|*/*) ;;
        *) repo="${json_image%:*}" ;;
    esac

    if [ -n "${WAZUH_DEVCONTAINER_IMAGE:-}" ]; then
        repo="$WAZUH_DEVCONTAINER_IMAGE"
        case "$repo" in
            *@*) die "WAZUH_DEVCONTAINER_IMAGE '$repo' carries a digest: set the repository alone." ;;
        esac
        case "${repo##*:}" in
            "$repo"|*/*) ;;
            *) die "WAZUH_DEVCONTAINER_IMAGE '$repo' carries a tag: set the repository alone." ;;
        esac
    fi

    # major.minor of VERSION.json ("5.0.0" -> "5.0")
    version=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([0-9][0-9]*\.[0-9][0-9]*\)[^"]*".*/\1/p' "$TMP_DIR/VERSION.json" | sed -n '1p')
    if [ -z "$version" ]; then
        die "cannot read the version from VERSION.json on branch '$BRANCH'."
    fi
    tag="$version"

    IMAGE="${repo}:${tag}"

    # Registry: the first path component when it looks like a host, Docker Hub otherwise
    first="${repo%%/*}"
    rest="${repo#*/}"
    case "$first" in
        "$repo") REGISTRY="docker.io"; rest="$repo" ;;
        *.*|*:*|localhost) REGISTRY="$first" ;;
        *) REGISTRY="docker.io"; rest="$repo" ;;
    esac
    OWNER="${rest%%/*}"

}

# Return 0 when Docker has a credential stored for REGISTRY. Same lookup as Docker:
# credHelpers["<registry>"], then credsStore, then auths["<registry>"] of config.json.
registry_has_credential() {
    local config="${DOCKER_CONFIG:-$HOME/.docker}/config.json"
    local server="$REGISTRY"
    local flat key_regex helpers helper

    [ -f "$config" ] || return 1

    # Docker stores Docker Hub credentials under its legacy index URL
    if [ "$REGISTRY" = "docker.io" ]; then
        server="https://index.docker.io/v1/"
    fi

    # Keys may carry a scheme and a path (https://index.docker.io/v1/): match the host alone
    flat=$(tr -d '\n\r\t' < "$config")
    key_regex=${server#https://}
    key_regex=$(printf '%s' "${key_regex%%/*}" | sed 's/[].[*^$\\]/\\&/g')

    helper=""
    helpers=$(printf '%s' "$flat" | sed -n 's/.*"credHelpers"[[:space:]]*:[[:space:]]*{\([^}]*\)}.*/\1/p')
    if [ -n "$helpers" ]; then
        helper=$(printf '%s' "$helpers" | sed -n "s|.*\"\(https*://\)*${key_regex}\(/[^\"]*\)*\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*|\3|p")
    fi
    if [ -z "$helper" ]; then
        helper=$(printf '%s' "$flat" | sed -n 's/.*"credsStore"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    fi

    if [ -n "$helper" ]; then
        if ! command -v "docker-credential-$helper" > /dev/null 2>&1; then
            echo "Warning: Docker is configured to use the credential helper 'docker-credential-$helper', which is not in PATH." >&2
            return 1
        fi
        printf '%s' "$server" | "docker-credential-$helper" get > /dev/null 2>&1
        return
    fi

    # No helper: an auths entry with an auth or identitytoken value
    printf '%s' "$flat" | grep -E "\"(https?://)?${key_regex}(/[^\"]*)?\"[[:space:]]*:[[:space:]]*\\{[^}]*\"(auth|identitytoken)\"[[:space:]]*:[[:space:]]*\"[^\"]+\"" > /dev/null
}

# Print why the GitHub CLI route of the login menu cannot be used (nothing when it can)
gh_login_unavailable_reason() {
    if [ "$REGISTRY" != "ghcr.io" ]; then
        echo "the registry is not ghcr.io"
    elif [ -n "${GH_TOKEN:-}" ] || [ -n "${GITHUB_TOKEN:-}" ]; then
        # gh auth refresh does not work with a token from the environment
        echo "GH_TOKEN or GITHUB_TOKEN is set"
    elif ! command -v gh > /dev/null 2>&1; then
        echo "gh is not installed"
    elif ! gh auth status -h github.com > /dev/null 2>&1; then
        echo "gh is not logged in to github.com"
    fi
}

# Log in to REGISTRY with the GitHub CLI: the token goes through stdin only
login_with_gh() {
    local login

    local token

    gh auth refresh -h github.com -s read:packages || return 1
    if ! login=$(gh api user -q .login) || [ -z "$login" ]; then
        die "cannot read your GitHub login with gh (gh api user)."
    fi
    if ! token=$(gh auth token) || [ -z "$token" ]; then
        die "cannot read your GitHub token with gh (gh auth token)."
    fi
    printf '%s' "$token" | docker login "$REGISTRY" -u "$login" --password-stdin
}

# Log in to REGISTRY with a personal access token: read without echo, passed through stdin only
login_with_token() {
    local user token

    read -rp "GitHub user: " user || return 1
    read -rsp "Token: " token || { echo "" >&2; return 1; }
    echo "" >&2
    if [ -z "$user" ] || [ -z "$token" ]; then
        die "no GitHub user or token given."
    fi
    printf '%s' "$token" | docker login "$REGISTRY" -u "$user" --password-stdin
}

# Offer the login menu (only called with a terminal on stdin); exits on "3" or a failed login
login_menu() {
    local gh_ok=0
    local gh_note=""
    local choice

    gh_note=$(gh_login_unavailable_reason)
    if [ -z "$gh_note" ]; then
        gh_ok=1
    else
        gh_note=" (unavailable: ${gh_note})"
    fi

    {
        echo "The devContainer image ${IMAGE} is not accessible with your current Docker credentials."
        echo "Packages under ${REGISTRY}/${OWNER} are private: you need a GitHub account with access to them."
        echo "How do you want to log in to ${REGISTRY}?"
        echo "  1) With the GitHub CLI (gh auth refresh -s read:packages, then docker login with its token)${gh_note}"
        echo "  2) With a personal access token (classic) with the read:packages scope"
        echo "  3) Exit"
    } >&2

    while true; do
        if ! read -rp "Choice: " choice; then
            echo "" >&2
            exit 1
        fi
        case "$choice" in
            1)
                if [ "$gh_ok" -ne 1 ]; then
                    echo "option 1 is unavailable" >&2
                    continue
                fi
                login_with_gh || die "docker login to ${REGISTRY} failed."
                return 0
                ;;
            2)
                login_with_token || die "docker login to ${REGISTRY} failed."
                return 0
                ;;
            3)
                exit 1
                ;;
            *)
                echo "Please answer 1, 2 or 3." >&2
                ;;
        esac
    done
}

# Run `docker manifest inspect IMAGE`; on failure, its stderr is left in MANIFEST_ERROR
MANIFEST_ERROR=""
inspect_manifest() {
    if MANIFEST_ERROR=$(docker manifest inspect "$IMAGE" 2>&1 > /dev/null); then
        return 0
    fi
    return 1
}

# Exit with the error that matches MANIFEST_ERROR when it is not an authorization error
fail_unless_denied() {
    if grep -iE 'denied|unauthorized' > /dev/null <<< "$MANIFEST_ERROR"; then
        return 0
    fi
    if grep -i 'manifest unknown' > /dev/null <<< "$MANIFEST_ERROR"; then
        if [ -n "$JSON_IMAGE" ] && [ "${JSON_IMAGE##*:}" != "${IMAGE##*:}" ]; then
            die "${IMAGE} is not published (manifest unknown): devcontainer.json of branch '${BRANCH}' names ${JSON_IMAGE}, but its VERSION.json maps to the tag ${IMAGE##*:}; the \"image\" tag must be bumped on that branch (README: \"How the image is published\")."
        fi
        die "${IMAGE} is not published (manifest unknown) (README: \"How the image is published\")."
    fi
    die "cannot reach ${REGISTRY}: ${MANIFEST_ERROR%%$'\n'*}"
}

# Function to make sure Docker can read IMAGE, offering to log in when it has no credential
ensure_registry_access() {
    local still_denied="${IMAGE} is still not accessible with the credentials stored for ${REGISTRY}: your account has no access to the package, or the stored credential is old (a gh auth refresh revokes the previous token): run 'docker logout ${REGISTRY}' and try again (README: \"Troubleshooting\")."

    echo "Checking access to ${IMAGE}..."
    inspect_manifest && return 0
    fail_unless_denied

    # ghcr answers "denied" both for a private package and for a missing one
    if registry_has_credential; then
        die "$still_denied"
    fi
    if [ ! -t 0 ]; then
        die "${IMAGE} is not accessible and there is no terminal to log in. Log in first (README: \"Logging in to ghcr.io\") and run the script again."
    fi

    login_menu

    # One retry with the new credential
    inspect_manifest && return 0
    fail_unless_denied
    die "$still_denied"
}

# Function to pull the image before anything is written to the destination
pull_image() {
    echo "Pulling ${IMAGE}..."
    if ! docker pull "$IMAGE"; then
        die "failed to pull ${IMAGE}."
    fi
}

# Function to copy devContainer files
copy_devContainer() {
    echo "Copying devContainer files to ${DEV_CONTAINER_DESTINATION}..."

    # Verify source directory exists
    if [ ! -d "$TMP_DIR/$REPO_DEV_DIR" ]; then
        echo "Error: Source directory not found in the repository" >&2
        exit 1
    fi

    # Copy the devContainer folder to the destination; from here on, a failure removes it
    DEST_CREATED=1
    cp -r "$TMP_DIR/$REPO_DEV_DIR" "$DEV_CONTAINER_DESTINATION"

    # Remove the excluded files
    for file in "${EXCLUDED_FILES[@]}"; do
        rm -f "$DEV_CONTAINER_DESTINATION/$file"
    done

    # Remove the excluded folders
    for folder in "${EXCLUDE_FOLDERS[@]}"; do
        rm -rf "${DEV_CONTAINER_DESTINATION:?}/$folder"
    done

    # The source path exists on other branches without the devContainer config
    # (e.g. only the CI reinstall-cmake.sh), which would copy a directory that
    # cannot open as a devContainer. Fail loudly instead.
    if [ ! -f "$DEV_CONTAINER_DESTINATION/.devcontainer/devcontainer.json" ]; then
        echo "Error: no .devcontainer/devcontainer.json under '$REPO_DEV_DIR' on branch '$BRANCH'." >&2
        echo "       Pick a branch that ships the devContainer (e.g. -b 5.0.0)." >&2
        exit 1
    fi
}

# Function to patch the devcontainer.json name with a unique suffix (MM-DD xx)
patch_devcontainer_name() {
    local json_file="$DEV_CONTAINER_DESTINATION/.devcontainer/devcontainer.json"

    if [ ! -f "$json_file" ]; then
        echo "Warning: devcontainer.json not found at '$json_file', skipping name patch" >&2
        return
    fi

    local suffix
    suffix="$(date +%m-%d) $(printf '%02x' $((RANDOM % 256)))"

    sed_inplace "s/\"name\": \"\([^\"]*\)\"/\"name\": \"\1 - ${suffix}\"/" "$json_file"

    echo "DevContainer name patched with suffix: - ${suffix}"
}

# Function to point the "image" line of devcontainer.json to the pulled image
patch_devcontainer_image() {
    local json_file="$DEV_CONTAINER_DESTINATION/.devcontainer/devcontainer.json"
    local image_repl

    image_repl=$(sed_escape_replacement "$IMAGE")
    sed_inplace "s|^\([[:space:]]*\"image\":[[:space:]]*\"\)[^\"]*\"|\1${image_repl}\"|" "$json_file"

    echo "DevContainer will use image: ${IMAGE}"
}

# Function to copy the exported Claude Code setup into the devContainer workspace
copy_claude_package() {
    [ -z "$CLAUDE_PACKAGE" ] && return 0
    cp "$CLAUDE_PACKAGE" "$DEV_CONTAINER_DESTINATION/claude-portable.tar.gz"
    echo ""
    echo "Claude Code setup copied to: $DEV_CONTAINER_DESTINATION/claude-portable.tar.gz"
    echo "Once the devContainer is up (WAZUH_REPO cloned), run inside it, from the workspace folder:"
    echo "  tar xzf claude-portable.tar.gz -C /tmp claude/skills/claude-portable/scripts/claude-portable.sh"
    echo "  bash /tmp/claude/skills/claude-portable/scripts/claude-portable.sh import claude-portable.tar.gz"
}

# Function to make the devContainer clone the branch it was downloaded from
patch_devcontainer_clone_branch() {
    local json_file="$DEV_CONTAINER_DESTINATION/.devcontainer/devcontainer.json"
    local clone='git clone --recursive https://github.com/wazuh/wazuh.git'
    local branch_repl

    if [ ! -f "$json_file" ] || ! grep -qF "$clone" "$json_file"; then
        echo "Warning: clone command not found in '$json_file'; the devContainer will clone the default branch" >&2
        return
    fi
    if ! git check-ref-format --branch "$BRANCH" >/dev/null 2>&1; then
        echo "Warning: '$BRANCH' is not a valid branch name; the devContainer will clone the default branch" >&2
        return
    fi

    branch_repl=$(sed_escape_replacement "$BRANCH")
    sed_inplace "s|git clone --recursive https://github.com/wazuh/wazuh.git|git clone --recursive --branch ${branch_repl} https://github.com/wazuh/wazuh.git|" "$json_file"

    echo "DevContainer will clone branch: ${BRANCH}"
}

# Print the VS Code URI that opens the destination as a devContainer (hex of the host path)
vscode_folder_uri() {
    local encoded_path
    encoded_path=$(printf '%s' "$DEV_CONTAINER_DESTINATION" | od -An -tx1 | tr -d ' \n')
    printf 'vscode-remote://dev-container+%s/workspaces/%s\n' "$encoded_path" "$(basename "$DEV_CONTAINER_DESTINATION")"
}

# Print the VS Code CLI: `code` from PATH or, on macOS, the one inside the app bundle (not in PATH unless
# "Shell Command: Install 'code' command in PATH" was run). Prints nothing when there is none.
vscode_cli() {
    local app candidate
    if command -v code > /dev/null 2>&1; then
        printf '%s\n' "code"
        return 0
    fi
    if [ "$(uname -s)" = "Darwin" ]; then
        for app in "/Applications" "$HOME/Applications"; do
            candidate="$app/Visual Studio Code.app/Contents/Resources/app/bin/code"
            if [ -x "$candidate" ]; then
                printf '%s\n' "$candidate"
                return 0
            fi
        done
    fi
}

# Function to open in VSCode (only asks with a terminal on stdin)
open_in_vscode() {
    local open_vscode uri cli hint
    uri=$(vscode_folder_uri)
    cli=$(vscode_cli)
    hint="\"${cli:-code}\" --folder-uri=\"${uri}\""
    [ "${cli:-code}" = "code" ] && hint="code --folder-uri=\"${uri}\""

    if [ ! -t 0 ]; then
        echo ""
        echo "To open it in VSCode: ${hint}"
        return 0
    fi

    while true; do
        echo ""
        if ! read -rp "Do you want to open the devContainer in VSCode? (y/n): " open_vscode; then
            echo ""
            break
        fi

        case $open_vscode in
            [Yy]* )
                if [ -z "$cli" ]; then
                    echo "Warning: VSCode CLI 'code' is not available. Please open VSCode manually" >&2
                    echo "  ${hint}"
                    break
                fi

                if ! "$cli" --list-extensions 2>/dev/null | grep "ms-vscode-remote.remote-containers" > /dev/null; then
                    echo "Installing the Dev Containers extension..."
                    "$cli" --install-extension ms-vscode-remote.remote-containers \
                        || echo "Warning: could not install the Dev Containers extension" >&2
                fi

                echo "Opening the devContainer in VSCode..."
                "$cli" --folder-uri="${uri}" || echo "Warning: VSCode could not open ${uri}" >&2
                break
                ;;
            [Nn]* )
                break
                ;;
            * )
                echo "Please answer yes or no."
                ;;
        esac
    done
}

# Main script

# Parse command line arguments
while getopts ":d:b:c:h" opt; do
    case ${opt} in
        d )
            DEV_CONTAINER_DESTINATION=$OPTARG
            ;;
        b )
            BRANCH=$OPTARG
            ;;
        c )
            CLAUDE_PACKAGE=$OPTARG
            ;;
        h )
            show_usage
            exit 0
            ;;
        \? )
            echo "Error: Invalid option: -$OPTARG" >&2
            show_usage
            exit 1
            ;;
        : )
            echo "Error: Option -$OPTARG requires an argument" >&2
            show_usage
            exit 1
            ;;
    esac
done

README_URL="https://github.com/wazuh/wazuh/blob/${BRANCH}/tools/devContainer/README.md"

# Set default destination if not provided
if [ -z "$DEV_CONTAINER_DESTINATION" ]; then
    DEV_CONTAINER_DESTINATION="${OLD_PWD}/devContainer"
else
    DEV_CONTAINER_DESTINATION=$(abspath "$DEV_CONTAINER_DESTINATION")
fi

# Validate the Claude Code package before downloading anything
if [ -n "$CLAUDE_PACKAGE" ]; then
    # Read the whole listing first: grep -q would close the pipe early and pipefail would reject a valid package
    if [ ! -f "$CLAUDE_PACKAGE" ] || ! CLAUDE_LISTING=$(tar tzf "$CLAUDE_PACKAGE" 2>/dev/null) \
        || ! grep -qx 'PORTABLE-MANIFEST.txt' <<< "$CLAUDE_LISTING"; then
        echo "Error: $CLAUDE_PACKAGE is not a package exported by claude-portable.sh (no PORTABLE-MANIFEST.txt)" >&2
        exit 1
    fi
    CLAUDE_PACKAGE=$(abspath "$CLAUDE_PACKAGE")
fi

# Check if destination folder already exists
if [ -e "$DEV_CONTAINER_DESTINATION" ]; then
    echo "Error: The folder $DEV_CONTAINER_DESTINATION already exists" >&2
    exit 1
fi

# Validate prerequisites
check_prerequisites

# Download the repository
download_repo

# Check that the branch ships the prebuilt image (before the pull)
check_branch_files

# Compute the image of the branch
compute_image

# Make sure Docker can read the image (offers to log in), then pull it
ensure_registry_access
pull_image

# Copy the devContainer folder
copy_devContainer

# Patch the devcontainer.json name with a unique suffix
patch_devcontainer_name

# Make the devContainer clone the same branch
patch_devcontainer_clone_branch

# Point the devContainer to the pulled image
patch_devcontainer_image

# Copy the exported Claude Code setup, if any
copy_claude_package

# The destination is complete: a later failure (VS Code) must not remove it
DEST_CREATED=0

# Print success message
echo ""
echo "The devContainer image ${IMAGE} is ready."
echo "The devContainer folder has been downloaded successfully to: $DEV_CONTAINER_DESTINATION"
echo "  Branch: ${BRANCH}"

# Ask to open in VSCode
open_in_vscode

echo ""
echo "Done!"
