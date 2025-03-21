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
  WAZUH_GROUP='wazuh-server'
  WAZUH_USER='wazuh-server'
  INSTALL="install"

  ./init/adduser.sh ${WAZUH_USER} ${WAZUH_GROUP} ${INSTALLDIR}
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
    SHARE_INSTALLDIR="/usr/share/wazuh-server"

    ${MAKEBIN} --quiet -C ../framework install ${SHARE_INSTALLDIR}
    ${PYTHON_BIN_PATH} -m pip install ../framework/

    ## Install Server management API
    ${MAKEBIN} --quiet -C ../apis/server_management install ${SHARE_INSTALLDIR}
    ${PYTHON_BIN_PATH} -m pip install ../apis/server_management

    ## Install Communications API
    ${MAKEBIN} --quiet -C ../apis/communications install ${SHARE_INSTALLDIR}
    ${PYTHON_BIN_PATH} -m pip install ../apis/communications

    ${INSTALL} -m 440 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ../VERSION.json ${SHARE_INSTALLDIR}/VERSION.json

}

checkDownloadContent()
{
    VD_FILENAME='vd_1.0.0_vd_4.10.0.tar.xz'
    VD_FULL_PATH=${INSTALLDIR}var/lib/wazuh-server/tmp/${VD_FILENAME}

    if [ "X${DOWNLOAD_CONTENT}" = "Xy" ]; then
        echo "Download ${VD_FILENAME} file"
        mkdir -p ${INSTALLDIR}var/lib/wazuh-server/tmp/
        wget -O ${VD_FULL_PATH} http://packages.wazuh.com/deps/vulnerability_model_database/${VD_FILENAME}

        chmod 640 ${VD_FULL_PATH}
        chown ${WAZUH_USER}:${WAZUH_GROUP} ${VD_FULL_PATH}
    fi
}

# Install the fallback store
installFallbackStore()
{
    # Creating fallback store directories
    local STORE_PATH=${INSTALLDIR}var/lib/wazuh-server/engine/store
    local KVDB_PATH=${INSTALLDIR}var/lib/wazuh-server/engine/kvdb
    local SCHEMA_PATH=${STORE_PATH}/schema
    local ENGINE_SCHEMA_PATH=${SCHEMA_PATH}/engine-schema/
    local ENGINE_LOGPAR_TYPE_PATH=${SCHEMA_PATH}/wazuh-logpar-overrides

    mkdir -p "${KVDB_PATH}"
    mkdir -p "${ENGINE_SCHEMA_PATH}"
    mkdir -p "${ENGINE_LOGPAR_TYPE_PATH}"

    # Copying the store files
    echo "Copying store files..."
    cp "${ENGINE_SRC_PATH}/ruleset/schemas/engine-schema.json" "${ENGINE_SCHEMA_PATH}/0"
    cp "${ENGINE_SRC_PATH}/ruleset/schemas/wazuh-logpar-overrides.json" "${ENGINE_LOGPAR_TYPE_PATH}/0"

    if [ ! -f "${ENGINE_SCHEMA_PATH}/0" ] || [ ! -f "${ENGINE_LOGPAR_TYPE_PATH}/0" ]; then
        echo "Error: Failed to copy store files."
        exit 1
    fi

    chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${STORE_PATH}
    chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${KVDB_PATH}
    find ${STORE_PATH} -type d -exec chmod 750 {} \; -o -type f -exec chmod 640 {} \;
    find ${KVDB_PATH} -type d -exec chmod 750 {} \; -o -type f -exec chmod 640 {} \;
}

installEngineStore()
{
    DEST_FULL_PATH=${INSTALLDIR}var/lib/wazuh-server
    LOCAL_PRECOMPILED_STORE_PATH="${ENGINE_SRC_PATH}/engine_precompiled_store.tar.gz"

    echo "Checking for precompiled store file...$LOCAL_PRECOMPILED_STORE_PATH"
    if [ -f "${LOCAL_PRECOMPILED_STORE_PATH}" ]; then
        echo "Using precompiled store file ${LOCAL_PRECOMPILED_STORE_PATH}"
    else
        echo "Installing fallback store..."
        installFallbackStore
        return
    fi


    chmod 640 ${LOCAL_PRECOMPILED_STORE_PATH}
    chown ${WAZUH_USER}:${WAZUH_GROUP} ${LOCAL_PRECOMPILED_STORE_PATH}

    echo "Extracting ${LOCAL_PRECOMPILED_STORE_PATH} to ${DEST_FULL_PATH}..."
    if ! tar -xzf ${LOCAL_PRECOMPILED_STORE_PATH} -C ${DEST_FULL_PATH}; then
        echo "Error: Failed to extract ${LOCAL_PRECOMPILED_STORE_PATH} to ${DEST_FULL_PATH}"
        exit 1
    fi

    echo "Removing tar file ${LOCAL_PRECOMPILED_STORE_PATH}..."
    if ! rm -f ${LOCAL_PRECOMPILED_STORE_PATH}; then
        echo "Warning: Failed to remove tar file ${LOCAL_PRECOMPILED_STORE_PATH}."
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

  # Folder for persistent databases (vulnerability scanner, ruleset, connector).
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/vd
  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine

  cp -rp engine/build/tzdb ${INSTALLDIR}var/lib/wazuh-server/engine/
  chown -R ${WAZUH_USER}:${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/engine/tzdb
  chmod 0750 ${INSTALLDIR}var/lib/wazuh-server/engine/tzdb
  chmod 0640 ${INSTALLDIR}var/lib/wazuh-server/engine/tzdb/*

  ${INSTALL} -d -m 0750 -o ${WAZUH_USER} -g ${WAZUH_GROUP} ${INSTALLDIR}var/lib/wazuh-server/indexer-connector

  # Download and extract the Engine store
  installEngineStore
}

InstallKeystore()
{
  ${INSTALL} -m 0750 -o root -g ${WAZUH_GROUP} engine/build/source/keystore/wazuh-keystore ${INSTALLDIR}usr/share/wazuh-server/bin/wazuh-keystore
}

InstallWazuh()
{
  InstallCommon
  InstallEngine
  InstallKeystore
  InstallPython
  InstallPythonDependencies
  InstallServer
}

BuildEngine()
{
  ENGINE_SRC_PATH=$(pwd)/engine
  cd "${ENGINE_SRC_PATH}"

  # Configure the engine
  cmake --preset=relwithdebinfo --no-warn-unused-cli
  # Compile only the engine
  cmake --build build --target main -j $(nproc)

  cd ..
}

BuildKeystore()
{
  cd engine

  # Compile only the engine
  cmake --build build --target wazuh-keystore -j $(nproc)

  cd ..
}
