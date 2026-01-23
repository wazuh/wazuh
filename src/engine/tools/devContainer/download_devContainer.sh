#!/bin/bash

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Save current directory
readonly OLD_PWD=$(pwd)

# Constants
readonly TMP_DIR="/tmp/wazuh_devContainer_$$"  # Use PID for unique temp dir
readonly REPO_DEV_DIR="src/engine/tools/devContainer"
readonly REPO_URL="https://github.com/wazuh/wazuh.git"
readonly DEFAULT_BRANCH="main"

readonly EXCLUDED_FILES=(
    "download_devContainer.sh"
    "README.md"
)

readonly EXCLUDE_FOLDERS=(
    "scripts"
    "e2e"
)

# Variables
BRANCH="${DEFAULT_BRANCH}"
DEV_CONTAINER_DESTINATION=""

# Clean up the temporary directory
cleanup() {
    cd "$OLD_PWD"
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Function to show usage
show_usage() {
    cat << EOF
Usage: $(basename "$0") [-d <destination>] [-b <branch>] [-h]

Options:
    -d    Destination directory for devContainer (default: ./devContainer)
    -b    Git branch to download from (default: ${DEFAULT_BRANCH})
    -h    Show this help message

Examples:
    $(basename "$0")
    $(basename "$0") -d ~/my-devcontainer
    $(basename "$0") -b development -d /tmp/devcontainer
EOF
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

    # Check if the user is in the docker group
    if ! groups | grep -q "\bdocker\b"; then
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

    # sparse-checkout for the specific folders
    git sparse-checkout init --cone
    git sparse-checkout set "$REPO_DEV_DIR"
    git checkout "${BRANCH}"

    cd "$OLD_PWD" || exit 1
}

# Function to copy devContainer files
copy_devContainer() {
    echo "Copying devContainer files to ${DEV_CONTAINER_DESTINATION}..."

    # Verify source directory exists
    if [ ! -d "$TMP_DIR/$REPO_DEV_DIR" ]; then
        echo "Error: Source directory not found in the repository" >&2
        exit 1
    fi

    # Copy the devContainer folder to the destination
    cp -r "$TMP_DIR/$REPO_DEV_DIR" "$DEV_CONTAINER_DESTINATION"

    # Remove the excluded files
    for file in "${EXCLUDED_FILES[@]}"; do
        rm -f "$DEV_CONTAINER_DESTINATION/$file"
    done

    # Remove the excluded folders
    for folder in "${EXCLUDE_FOLDERS[@]}"; do
        rm -rf "$DEV_CONTAINER_DESTINATION/$folder"
    done
}

# Function to open in VSCode
open_in_vscode() {
    while true; do
        echo ""
        read -rp "Do you want to open the devContainer in VSCode? (y/n): " open_vscode

        case $open_vscode in
            [Yy]* )
                if ! command -v code &> /dev/null; then
                    echo "Warning: VSCode CLI 'code' is not available. Please open VSCode manually" >&2
                    break
                fi

                cd "$DEV_CONTAINER_DESTINATION" || exit 1

                if ! code --list-extensions 2>/dev/null | grep -q "ms-vscode-remote.remote-containers"; then
                    echo "Installing the Remote - Containers extension..."
                    code --install-extension ms-vscode-remote.remote-containers
                fi

                echo "Opening the devContainer in VSCode..."
                local encoded_path
                encoded_path=$(pwd | tr -d '\n' | xxd -c 256 -p)
                code --folder-uri="vscode-remote://dev-container+${encoded_path}/workspaces/$(basename "$(pwd)")"
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
while getopts ":d:b:h" opt; do
    case ${opt} in
        d )
            DEV_CONTAINER_DESTINATION=$OPTARG
            ;;
        b )
            BRANCH=$OPTARG
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

# Set default destination if not provided
if [ -z "$DEV_CONTAINER_DESTINATION" ]; then
    DEV_CONTAINER_DESTINATION="${OLD_PWD}/devContainer"
else
    DEV_CONTAINER_DESTINATION=$(realpath "$DEV_CONTAINER_DESTINATION")
fi

# Check if destination folder already exists
if [ -d "$DEV_CONTAINER_DESTINATION" ]; then
    echo "Error: The folder $DEV_CONTAINER_DESTINATION already exists" >&2
    exit 1
fi

# Validate prerequisites
check_prerequisites

# Download the repository
download_repo

# Copy the devContainer folder
copy_devContainer

# Print success message
echo ""
echo "The devContainer folder has been downloaded successfully to: $DEV_CONTAINER_DESTINATION"
echo "  Branch: ${BRANCH}"

# Ask to open in VSCode
open_in_vscode

echo ""
echo "Done!"
