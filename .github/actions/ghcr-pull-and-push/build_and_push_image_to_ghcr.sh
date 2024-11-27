GITHUB_PUSH_SECRET=$1
GITHUB_USER=$2
DOCKER_IMAGE_NAME=$3
BUILD_CONTEXT=$4
DOCKERFILE_PATH="$BUILD_CONTEXT/Dockerfile"
if [ -n "$5" ]; then
    DOCKER_IMAGE_TAG=$5
else
    exit 1
fi
GITHUB_REPOSITORY="wazuh/wazuh"
GITHUB_OWNER="wazuh"
IMAGE_ID=ghcr.io/${GITHUB_OWNER}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}
IMAGE_ID=$(echo ${IMAGE_ID} | tr '[A-Z]' '[a-z]')

# Extract the architecture from DOCKER_IMAGE_NAME
ARCHITECTURE=$(echo $DOCKER_IMAGE_NAME | awk -F'_' '{print $NF}')

# Login to GHCR
echo ${GITHUB_PUSH_SECRET} | docker login https://ghcr.io -u $GITHUB_USER --password-stdin

# Build image for the specified architecture
echo build -t ${IMAGE_ID} -f ${DOCKERFILE_PATH} ${BUILD_CONTEXT}
docker build --platform linux/$ARCHITECTURE -t ${IMAGE_ID} -f ${DOCKERFILE_PATH} ${BUILD_CONTEXT}

# Push the built image
docker push ${IMAGE_ID}
