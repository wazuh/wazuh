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
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}run/wazuh-engine
  # Folder for persistent databases (vulnerability scanner, ruleset, connector).
  ${INSTALL} -d -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-engine
  # Folder for persistent databases (vulnerability scanner).
  ${INSTALL} -d -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-engine/vd
  # Folder for persistent databases (ruleset).
  ${INSTALL} -d -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-engine/ruleset
  # Folder for persistent queues for the indexer connector.
  ${INSTALL} -d -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-engine/indexer-connector

}

InstallPython()
{
    PYTHON_VERSION='3.10.15'
    PYTHON_FILENAME='python.tar.gz'
    PYTHON_INSTALLDIR=${INSTALLDIR}usr/share/wazuh-server/framework/python/
    PYTHON_FULL_PATH=${PYTHON_INSTALLDIR}$PYTHON_FILENAME

    echo "Download Python ${PYTHON_VERSION} file"
    mkdir -p ${PYTHON_INSTALLDIR}
    wget -O ${PYTHON_FULL_PATH} http://packages.wazuh.com/deps/50/libraries/python/${PYTHON_VERSION}/${PYTHON_FILENAME}

    tar -xf $PYTHON_FULL_PATH -C ${PYTHON_INSTALLDIR} && rm -rf ${PYTHON_FULL_PATH}

    mkdir -p ${INSTALLDIR}usr/share/wazuh-server/lib

    ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${PYTHON_INSTALLDIR}lib/libwazuhext.so ${INSTALLDIR}usr/share/wazuh-server/lib
    ${INSTALL} -m 0660 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${PYTHON_INSTALLDIR}lib/libpython3.10.so.1.0 ${INSTALLDIR}usr/share/wazuh-server/lib

    chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${PYTHON_INSTALLDIR}
}

InstallPythonDependencies()
{
    PYTHON_BIN_PATH=${INSTALLDIR}usr/share/wazuh-server/framework/python/bin/python3

    echo "Installing Python dependecies"
    ${PYTHON_BIN_PATH} -m pip install -r ../framework/requirements.txt
}

InstallServer()
{
    PYTHON_BIN_PATH=${INSTALLDIR}usr/share/wazuh-server/framework/python/bin/python3

    ${MAKEBIN} --quiet -C ../framework install INSTALLDIR=/usr/share/wazuh-server
    ${PYTHON_BIN_PATH} -m pip install ../framework/

    ## Install Server management API
    ${MAKEBIN} --quiet -C ../api install INSTALLDIR=/usr/share/wazuh-server
    ${PYTHON_BIN_PATH} -m pip install ../api/

    ## Install Communications API
    ${MAKEBIN} --quiet -C ../apis/comms_api install INSTALLDIR=/usr/share/wazuh-server
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

installEngineStore()
{
    STORE_FILENAME='engine_store_0.0.2_5.0.0.tar.gz'
    STORE_FULL_PATH=${INSTALLDIR}tmp/wazuh-server/${STORE_FILENAME}
    STORE_URL=https://packages.wazuh.com/deps/engine_store_model_database/${STORE_FILENAME}
    DEST_FULL_PATH=${INSTALLDIR}var/lib/wazuh-server

    echo "Downloading ${STORE_FILENAME} file..."
    mkdir -p ${INSTALLDIR}tmp/wazuh-server
    if ! wget -O ${STORE_FULL_PATH} ${STORE_URL}; then
        echo "Error: Failed to download ${STORE_FILENAME} from ${STORE_URL}"
        exit 1
    fi

    chmod 640 ${STORE_FULL_PATH}
    chown ${WAZUH_USER}:${WAZUH_GROUP} ${STORE_FULL_PATH}

    echo "Extracting ${STORE_FILENAME} to ${DEST_FULL_PATH}..."
    if ! tar -xzf ${STORE_FULL_PATH} -C ${DEST_FULL_PATH}; then
        echo "Error: Failed to extract ${STORE_FILENAME} to ${DEST_FULL_PATH}"
        exit 1
    fi

    echo "Removing tar file ${STORE_FULL_PATH}..."
    if ! rm -f ${STORE_FULL_PATH}; then
        echo "Warning: Failed to remove tar file ${STORE_FULL_PATH}."
    fi

    chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${DEST_FULL_PATH}/engine/store
    chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${DEST_FULL_PATH}/engine/kvdb
    find ${DEST_FULL_PATH}/engine/store -type d -exec chmod 750 {} \; -o -type f -exec chmod 640 {} \;
    find ${DEST_FULL_PATH}/engine/kvdb -type d -exec chmod 750 {} \; -o -type f -exec chmod 640 {} \;
    
    echo "Verifying store installation..."
    if [ ! -d "${DEST_FULL_PATH}/engine/store" ] || [ ! -d "${DEST_FULL_PATH}/engine/kvdb" ]; then
        echo "Error: Store installation verification failed. Required directories are missing."
        exit 1
    fi

    echo "Engine store installed successfully."

}


InstallEngine()
{
  # Check if the content needs to be downloaded.
  checkDownloadContent
  mkdir -p ${INSTALLDIR}usr/share/wazuh-server/bin
  ${INSTALL} -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} engine/build/main ${INSTALLDIR}usr/share/wazuh-server/bin/wazuh-engine

  # Folder for the engine socket.
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}run/wazuh-server/

  # Folder for persistent databases (vulnerability scanner, ruleset, connector).
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/vd
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine
  ${INSTALL} -d -m 0755 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/log/wazuh-server
  ${INSTALL} -d -m 0755 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/log/wazuh-server/engine

  cp -rp engine/build/tzdb ${INSTALLDIR}var/lib/wazuh-server/engine/
  chown -R root:${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine/tzdb
  chmod 0750 ${INSTALLDIR}var/lib/wazuh-server/engine/tzdb
  chmod 0640 ${INSTALLDIR}var/lib/wazuh-server/engine/tzdb/*

  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/indexer-connector

  # Download and extract the Engine store
  installEngineStore
}

InstallWazuh()
{
  InstallCommon
  InstallEngine
  InstallPython
  InstallPythonDependencies
  InstallServer
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
