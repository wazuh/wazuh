#!/bin/bash

# Save current directory
OLD_PWD=$(pwd)

# Clean up the temporary directory
trap 'cd "$OLD_PWD";rm -rf "$TMP_DIR"' EXIT

TMP_DIR="/tmp/wazuh_devContainer"
REPO_DEV_DIR="src/engine/tools/devContainer"
REPO_URL="https://github.com/wazuh/wazuh.git"
BRANCH="master"

EXCLUDED_FILES=(
    "download_devContainer.sh"
    "README.md"
)

download_repo() {
    # Clone the minimal repository
    rm -rf "$TMP_DIR"
    mkdir -p "$TMP_DIR" && cd "$TMP_DIR" || exit
    git clone --filter=blob:none --branch ${BRANCH}  --no-checkout --depth 1 --sparse "$REPO_URL" .

    # sparse-checkout for the specific folders
    git sparse-checkout init --cone
    git sparse-checkout set "$REPO_DEV_DIR"
    git checkout "${BRANCH}"
}

copy_devContainer() {
    # Copy the devContainer folder to the current directory
    cp -r "$TMP_DIR/$REPO_DEV_DIR" "$DEV_CONTAINER_DESTINATION"

    # Remove the excluded files
    for file in "${EXCLUDED_FILES[@]}"; do
        rm -f "$DEV_CONTAINER_DESTINATION/$file"
    done
}

# Check if docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker before running this script"
    exit 1
fi

# Check if docker is running
if ! docker info &> /dev/null; then
    echo "Docker is not running. Please start Docker before running this script"
    exit 1
fi

# Check if the user is in the docker group
if ! groups | grep -q "\bdocker\b"; then
    echo "The user is not in the docker group. Please add the user to the docker group before running this script"
    exit 1
fi

# Read parameters of the script
# -d: devContainer destination, default is the $(pwd)/devContainer
while getopts ":d:" opt; do
    case ${opt} in
        d )
            DEV_CONTAINER_DESTINATION=$OPTARG
            ;;
        \? )
            echo "Usage: download_devContainer.sh [-d <devContainer_destination>]"
            exit 1
            ;;
    esac
done

# Check if the destination is set
if [ -z "$DEV_CONTAINER_DESTINATION" ]; then
    DEV_CONTAINER_DESTINATION=${OLD_PWD}/devContainer
else
    DEV_CONTAINER_DESTINATION=$(realpath "$DEV_CONTAINER_DESTINATION")
fi

# If folder exists, exit
if [ -d "$DEV_CONTAINER_DESTINATION" ]; then
    echo "The folder $DEV_CONTAINER_DESTINATION already exists"
    exit 1
fi

# Download the repository
download_repo

# Copy the devContainer folder
copy_devContainer

# Print the success message
echo "The devContainer folder has been downloaded to $DEV_CONTAINER_DESTINATION"

while true; do
    echo "Do you want to open the devContainer in VSCode? (y/n)"
    read -r open_vscode

    case $open_vscode in
        [Yy]* )
            cd "$DEV_CONTAINER_DESTINATION"
            if ! code --list-extensions | grep -q "ms-vscode-remote.remote-containers"; then
                echo "Installing the Remote - Containers extension"
                code --install-extension ms-vscode-remote.remote-containers
            fi
            echo "Opening the devContainer in VSCode"
            code --folder-uri="vscode-remote://dev-container+$(pwd | tr -d '\n' | xxd -c 256 -p)/workspaces/$(basename "$(pwd)")"
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
