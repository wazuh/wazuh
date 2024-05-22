set -x
GITHUB_PUSH_SECRET=$1
GITHUB_USER=$2
OLD_TAG=$3
NEW_TAG=$4
if [ -n "$5" ]; then
    SINGLE_IMAGE="$5"
fi

IMAGES_LIST=(
    "common_wpk_builder"
    "compile_windows_agent"
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

retag_image(){
    DOCKER_IMAGE_NAME="$1"
    OLD_TAG="$2"
    NEW_TAG="$3"
    GITHUB_REPOSITORY="wazuh/wazuh"
    GITHUB_OWNER="wazuh"
    IMAGE_ID=$(echo "ghcr.io/${GITHUB_OWNER}/${DOCKER_IMAGE_NAME}" | tr '[A-Z]' '[a-z]')

    # Bring old tag
    pull_output=$(docker pull ${IMAGE_ID}:${OLD_TAG})

    if echo "$pull_output" | grep -qi "error"; then
        echo "Failed pulling ${IMAGE_ID}:${OLD_TAG}"
        exit 1
    else
        # Retag
        docker tag ${IMAGE_ID}:${OLD_TAG} ${IMAGE_ID}:${NEW_TAG}
        # Upload
        docker push ${IMAGE_ID}:${NEW_TAG}
        docker rmi ${IMAGE_ID}:${OLD_TAG} -f
        docker rmi ${IMAGE_ID}:${NEW_TAG} -f
    fi
}

# Login to GHCR
echo ${GITHUB_PUSH_SECRET} | docker login https://ghcr.io -u $GITHUB_USER --password-stdin

if [ -n "$SINGLE_IMAGE" ]; then
    # Retag the image passed as argument
    retag_image $SINGLE_IMAGE $OLD_TAG $NEW_TAG
else
    # Iterate images list retagging
    for DOCKER_IMAGE_NAME in "${IMAGES_LIST[@]}"; do
        retag_image $DOCKER_IMAGE_NAME $OLD_TAG $NEW_TAG
    done
fi
