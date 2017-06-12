#!/bin/sh

# Wazuh Agent Package Generator
# Copyright (C) 2017 Wazuh Inc.
# June 9, 2017.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


Add_Preloaded(){
    echo 'USER_UPDATE="y"' >> ./etc/preloaded-vars.conf
    echo 'USER_LANGUAGE="en"' >> ./etc/preloaded-vars.conf
    echo 'USER_NO_STOP="y"' >> ./etc/preloaded-vars.conf
    echo 'USER_BINARYINSTALL="y"'>> ./etc/preloaded-vars.conf
    echo 'USER_INSTALL_TYPE="agent"' >> ./etc/preloaded-vars.conf
}

# Copy the wazuh folder
rm -rf /tmp/wazuh_pkg
mkdir /tmp/wazuh_pkg
cp -r ./* /tmp/wazuh_pkg/
mv /tmp/wazuh_pkg ./

# Compiling agent
cd ./wazuh_pkg/src
make TARGET=agent
cd ..

# Cleaning
# rm -rf ./contrib
rm -rf ./doc
rm -rf ./wodles/oscap/content/*
#rm -rf ./extensions
rm -rf ./framework
#rm -rf ./integrations
rm gen_ossec.sh
rm add_localfiles.sh
rm gen_agent_pkg.sh
rm Jenkinsfile*

rm -rf ./src/addagent
# rm -rf ./src/agent-auth
# rm -rf ./src/agentlessd
rm -rf ./src/analysisd
rm -rf ./src/client-agent
rm -rf ./src/config
rm -rf ./src/error_messages
rm -rf ./src/external/cJSON
rm -rf ./src/external/sqlite
rm -rf ./src/external/zlib
rm -rf ./src/external/lua-5.2.3/src/*.c
rm -rf ./src/external/lua-5.2.3/src/*.h
rm -rf ./src/external/lua-5.2.3/src/*.o
rm -rf ./src/external/lua-5.2.3/src/*.a
rm -rf ./src/headers
rm -rf ./src/logcollector
# rm -rf ./src/manage_agents
rm -rf ./src/monitord
rm -rf ./src/os_auth
rm -rf ./src/os_crypto
rm -rf ./src/os_csyslogd
rm -rf ./src/os_dbd
rm -rf ./src/os_execd
rm -rf ./src/os_integrator
rm -rf ./src/os_maild
rm -rf ./src/os_net
rm -rf ./src/os_regex
rm -rf ./src/os_xml
rm -rf ./src/os_zlib
rm -rf ./src/remoted
rm -rf ./src/reportd
# rm -rf ./src/rootcheck
rm -rf ./src/shared
rm -rf ./src/syscheckd
# rm -rf ./src/systemd
rm -rf ./src/tests
rm -rf ./src/update
# rm -rf ./src/util
rm -rf ./src/wazuh_db
rm -rf ./src/wazuh_modules
# rm -rf ./src/wazuh-modulesd
rm -rf ./src/win32

rm -rf ./src/*.a

rm -rf ./etc/decoders
rm -rf ./etc/lists
rm -rf ./etc/rules

mv ./etc/templates/en ./etc
rm -rf ./etc/templates/*
mv ./etc/en ./etc/templates

# Generating unattended installation script
Add_Preloaded

cd ..
tar -zcf wazuh_agent.tar.gz wazuh_pkg/
