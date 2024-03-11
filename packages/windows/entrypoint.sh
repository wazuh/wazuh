#! /bin/bash

set -ex

BRANCH=$1
JOBS=$2
DEBUG=$3
REVISION=$4
TRUST_VERIFICATION=$5
CA_NAME=$6

URL_REPO=https://github.com/wazuh/wazuh/archive/${BRANCH}.zip

# Download the wazuh repository
wget -O wazuh.zip ${URL_REPO} && unzip wazuh.zip

# Compile the wazuh agent for Windows
FLAGS="-j ${JOBS} IMAGE_TRUST_CHECKS=${TRUST_VERIFICATION} CA_NAME=\"${CA_NAME}\" "

if [[ "${DEBUG}" = "yes" ]]; then
    FLAGS+="-d "
fi

bash -c "make -C /wazuh-*/src deps TARGET=winagent ${FLAGS}"
bash -c "make -C /wazuh-*/src TARGET=winagent ${FLAGS}"

rm -rf /wazuh-*/src/external

# Zip the compiled agent and move it to the shared folder
short_commit_hash="$(curl -s https://api.github.com/repos/wazuh/wazuh/commits/${BRANCH} \
                          | grep '"sha"' | head -n 1| cut -d '"' -f 4 | cut -c 1-7)"
version="$(cat /wazuh-*/src/VERSION| cut -d 'v' -f 2)"
ZIP_NAME="wazuh_agent_${version}-${REVISION}_windows_${short_commit_hash}.zip"
zip -r ${ZIP_NAME} wazuh-*
cp ${ZIP_NAME} /shared
