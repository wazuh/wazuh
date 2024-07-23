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

# Login to GHCR
echo ${GITHUB_PUSH_SECRET} | docker login https://ghcr.io -u $GITHUB_USER --password-stdin

# Build image
echo build -t ${IMAGE_ID} -f ${DOCKERFILE_PATH} ${BUILD_CONTEXT}
docker build -t ${IMAGE_ID} -f ${DOCKERFILE_PATH} ${BUILD_CONTEXT}
docker push ${IMAGE_ID}
