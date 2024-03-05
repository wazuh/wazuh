#! /bin/bash

set -ex

BRANCH=$1
JOBS=$2
DEBUG=$3
REVISION=$4
TRUST_VERIFICATION=$5
CA_NAME=$6
ZIP_NAME="windows_agent_${REVISION}.zip"

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
zip -r ${ZIP_NAME} wazuh-*
cp ${ZIP_NAME} /shared
