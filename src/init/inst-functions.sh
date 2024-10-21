#!/bin/sh

# Wazuh Installer Functions
# Copyright (C) 2015, Wazuh Inc.
# November 18, 2016.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# File dependencies:
# ./src/init/shared.sh
# ./src/init/template-select.sh

##########
# GenerateService() $1=template
##########
GenerateService()
{
    SERVICE_TEMPLATE=./src/init/templates/${1}
    sed "s|WAZUH_HOME_TMP|${INSTALLDIR}|g" ${SERVICE_TEMPLATE}
}

InstallCommon()
{
  WAZUH_GROUP='wazuh'
  WAZUH_USER='wazuh'
  INSTALL="install"
  WAZUH_CONTROL_SRC='./init/wazuh-server.sh'

  ./init/adduser.sh ${WAZUH_USER} ${WAZUH_GROUP} ${INSTALLDIR}

  # Folder for the engine api socket
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}run/wazuh-engine
  # Folder for persistent databases (vulnerability scanner, ruleset, connector).
  ${INSTALL} -d -m 0660 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-engine
  # Folder for persistent databases (vulnerability scanner).
  ${INSTALL} -d -m 0660 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-engine/vd
  # Folder for persistent databases (ruleset).
  ${INSTALL} -d -m 0660 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-engine/ruleset
  # Folder for persistent queues for the indexer connector.
  ${INSTALL} -d -m 0660 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-engine/indexer-connector

}

InstallPython()
{
    PYTHON_VERSION='3.10.15'
    PYTHON_FILENAME='python.tar.gz'
    PYTHON_INSTALLDIR=${INSTALLDIR}var/lib/wazuh-server/framework/python/
    PYTHON_FULL_PATH=${PYTHON_INSTALLDIR}$PYTHON_FILENAME

    echo "Download Python ${PYTHON_VERSION} file"
    mkdir -p ${PYTHON_INSTALLDIR}
    wget -O ${PYTHON_FULL_PATH} http://packages.wazuh.com/deps/50/libraries/python/${PYTHON_VERSION}/${PYTHON_FILENAME}

    tar -xf $PYTHON_FULL_PATH -C ${PYTHON_INSTALLDIR} && rm -rf ${PYTHON_FULL_PATH}

    mkdir -p ${INSTALLDIR}var/lib/wazuh-server/lib

    ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${PYTHON_INSTALLDIR}lib/libwazuhext.so ${INSTALLDIR}var/lib/wazuh-server/lib
    ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${PYTHON_INSTALLDIR}lib/libpython3.10.so.1.0 ${INSTALLDIR}var/lib/wazuh-server/lib

    chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${PYTHON_INSTALLDIR}
}

InstallPythonDependencies()
{
    PYTHON_BIN_PATH=${INSTALLDIR}var/lib/wazuh-server/framework/python/bin/python3

    echo "Installing Python dependecies"
    ${PYTHON_BIN_PATH} -m pip install -r ../framework/requirements.txt
}

InstallAPI()
{
    PYTHON_BIN_PATH=${INSTALLDIR}var/lib/wazuh-server/framework/python/bin/python3

    # Install Task Manager files
    ${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}/queue/tasks

    ${MAKEBIN} --quiet -C ../framework install INSTALLDIR=/var/lib/wazuh-server
    ${PYTHON_BIN_PATH} -m pip install ../framework/

    ## Install Server management API
    ${MAKEBIN} --quiet -C ../api install INSTALLDIR=/var/lib/wazuh-server
    ${PYTHON_BIN_PATH} -m pip install ../api/

    ## Install Communications API
    ${MAKEBIN} --quiet -C ../apis/comms_api install INSTALLDIR=/var/lib/wazuh-server
    ${PYTHON_BIN_PATH} -m pip install ../apis/

}

checkDownloadContent()
{
    VD_FILENAME='vd_1.0.0_vd_4.10.0.tar.xz'
    VD_FULL_PATH=${INSTALLDIR}tmp/wazuh-server/${VD_FILENAME}

    if [ "X${DOWNLOAD_CONTENT}" = "Xy" ]; then
        echo "Download ${VD_FILENAME} file"
        mkdir -p ${INSTALLDIR}tmp/wazuh-server
        wget -O ${VD_FULL_PATH} http://packages.wazuh.com/deps/vulnerability_model_database/${VD_FILENAME}

        chmod 640 ${VD_FULL_PATH}
        chown ${WAZUH_USER}:${WAZUH_GROUP} ${VD_FULL_PATH}
    fi
}

InstallEngine()
{
  # Check if the content needs to be downloaded.
  checkDownloadContent
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} engine/build/main ${INSTALLDIR}bin/wazuh-engine

  # Folder for the engine socket.
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}run/wazuh-server/

  # Folder for persistent databases (vulnerability scanner, ruleset, connector).
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/vd
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine/store
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine/store/schema/
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine/store/schema/wazuh-logpar-types
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine/store/schema/wazuh-asset
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine/store/schema/wazuh-policy
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine/store/schema/engine-schema
  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine/kvdb
  #${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} engine/build/tzdb ${INSTALLDIR}var/lib/wazuh-server/engine/tzdb
  cp -rp engine/build/tzdb ${INSTALLDIR}var/lib/wazuh-server/engine/
  chown -R root:${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine/tzdb
  chmod 0750 ${INSTALLDIR}var/lib/wazuh-server/engine/tzdb
  chmod 0640 ${INSTALLDIR}var/lib/wazuh-server/engine/tzdb/*

  ${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/indexer-connector

  # Copy the engine configuration file
  ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} engine/ruleset/schemas/wazuh-logpar-types.json ${INSTALLDIR}var/lib/wazuh-server/engine/store/schema/wazuh-logpar-types/0
  ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} engine/ruleset/schemas/wazuh-asset.json ${INSTALLDIR}var/lib/wazuh-server/engine/store/schema/wazuh-asset/0
  ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} engine/ruleset/schemas/wazuh-policy.json ${INSTALLDIR}var/lib/wazuh-server/engine/store/schema/wazuh-policy/0
  ${INSTALL} -m 0640 -o root -g ${WAZUH_GROUP} engine/ruleset/schemas/engine-schema.json ${INSTALLDIR}var/lib/wazuh-server/engine/store/schema/engine-schema/0

}

#InstallCluster()
#{
  # Install cluster files
  #${INSTALL} -d -m 0770 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-cluster
#}

InstallWazuh()
{
  InstallCommon
  InstallEngine
  InstallPython
  InstallPythonDependencies
  InstallAPI
  #InstallCluster
}

BuildEngine()
{
  cd engine

  # Configure the engine
  cmake --preset=relwithdebinfo --no-warn-unused-cli
  # Compile only the engine
  cmake --build build --target main -j $(nproc)

  cd ..
}
