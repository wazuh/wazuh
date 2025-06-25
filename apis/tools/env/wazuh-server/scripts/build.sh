#!/usr/bin/env bash

# Clone the Wazuh repository
git clone "https://github.com/xadminx/wazuh.git" -b ${WAZUH_BRANCH} --single-branch --depth=1 ${WAZUH_ROOT}

cd ${WAZUH_ROOT}

git submodule update --init --recursive

# Install the server
USER_LANGUAGE="en"                   \
USER_NO_STOP="y"                     \
USER_CA_STORE="/path/to/my_cert.pem" \
DOWNLOAD_CONTENT="y"                 \
./install.sh
