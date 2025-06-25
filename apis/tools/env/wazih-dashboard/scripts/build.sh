#!/usr/bin/env bash

cd ./..

# Clone the Wazuh repository
git clone "https://github.com/wazuh/wazuh-dashboard.git" -b 6.0.0 --single-branch --depth=1 .

git submodule update --init --recursive
