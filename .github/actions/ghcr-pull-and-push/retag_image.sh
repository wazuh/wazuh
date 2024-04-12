set -x
GITHUB_PUSH_SECRET=$1
GITHUB_USER=$2
OLD_TAG=$3
if [ -n "$4" ]; then
    NEW_TAG="$4"
else
    exit 1
fi
GITHUB_REPOSITORY="wazuh/wazuh"
GITHUB_OWNER="wazuh"

IMAGES_LIST=(
    "common_wpk_builder"
    "compile_windows_agent"
    "linux_wpk_builder_x86_64"
    "pkg_deb_agent_builder_i386"
    "pkg_deb_agent_builder_amd64"
    "pkg_deb_agent_builder_arm64"
    "pkg_deb_agent_builder_armhf"
    "pkg_deb_manager_builder_amd64"
    "pkg_rpm_agent_builder_i386"
    "pkg_rpm_agent_builder_amd64"
    "pkg_rpm_agent_builder_arm64"
    "pkg_rpm_agent_builder_armhf"
    "pkg_rpm_manager_builder_amd64"
    "pkg_rpm_legacy_builder_i386"
    "pkg_rpm_legacy_builder_amd64"
)

# Login to GHCR
echo ${GITHUB_PUSH_SECRET} | docker login https://ghcr.io -u $GITHUB_USER --password-stdin

# Iterate images list retagging
for DOCKER_IMAGE_NAME in "${IMAGES_LIST[@]}"; do
    IMAGE_ID=ghcr.io/${GITHUB_OWNER}/${DOCKER_IMAGE_NAME}
    IMAGE_ID=$(echo ${IMAGE_ID} | tr '[A-Z]' '[a-z]')

    # Bring old tag
    pull_output=$(docker pull ${IMAGE_ID}:${OLD_TAG})

    if echo "$pull_output" | grep -qi "error"; then
        echo "Failed pulling ${IMAGE_ID}:${OLD_TAG}"
    else
        # Retag
        docker tag ${IMAGE_ID}:${OLD_TAG} ${IMAGE_ID}:${NEW_TAG}
        # Upload
        docker push ${IMAGE_ID}:${NEW_TAG}
    fi
done
