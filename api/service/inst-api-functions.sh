#!/bin/sh

# Wazuh API Installer Functions
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


API_PATH=${PREFIX}/api
API_PATH_BACKUP=${PREFIX}/~api



stop_api_3x(){
    # stop api process if its still running
    OLD_API_PID=$(pgrep -f "${API_PATH}/app.js")
    if [ -n "$OLD_API_PID" ]; then
        echo "killing old api process: ${OLD_API_PID}"
        kill -9 "${OLD_API_PID}"
    fi
}



stop_api_4x() {
    "${PREFIX}"/bin/wazuh-apid stop
}



backup_old_api() {

    if [ $# -ne 1 ]; then
        echo "Backup_old_api requires the REVISION of the existing API"
        exit 1
    fi

    # remove backup folder and its contents if exists
    if [ -e "${API_PATH_BACKUP}" ]; then
        rm -rf "${API_PATH_BACKUP}"
    fi

    # check current REVISION and perform the applicable backup
    if [ "$1" -ge 40000 ]; then
        stop_api_4x
        backup_old_api_4x
    else
        stop_api_3x
    fi

    # remove old API directory
    rm -rf "${API_PATH}"
}



backup_old_api_4x() {

    # backup files only if configuration folder exists and its not empty
    if [ -d "${API_PATH}"/configuration ]; then
        if [ -n "$(ls -A "${API_PATH}"/configuration)" ]; then

            install -o root -g ossec -m 0770 -d "${API_PATH_BACKUP}"/configuration

            # backup API yaml if exists
            if [ -e "${API_PATH}"/configuration/api.yaml ]; then
                cp -rLfp "${API_PATH}"/configuration/api.yaml "${API_PATH_BACKUP}"/configuration/
            fi

            # backup security files if the folder exists and its not empty
            if [ -d "${API_PATH}"/configuration/security ]; then
                if [ -n "$(ls -A "${API_PATH}"/configuration/security)" ]; then
                    install -o root -g ossec -m 0770 -d "${API_PATH_BACKUP}"/configuration/security
                    cp -rLfp "${API_PATH}"/configuration/security/* "${API_PATH_BACKUP}"/configuration/security
                fi
            fi

            # backup ssl files if the folder exists and its not empty
            if [ -d "${API_PATH}"/configuration/ssl ]; then
                if [ -n "$(ls -A "${API_PATH}"/configuration/ssl)" ]; then
                    install -o root -g ossec -m 0770 -d "${API_PATH_BACKUP}"/configuration/ssl
                    cp -rLfp "${API_PATH}"/configuration/ssl/* "${API_PATH_BACKUP}"/configuration/ssl
                fi
            fi
        fi
    fi
}



restore_old_api() {

    if [ $# -ne 1 ]; then
        echo "restore_old_api requires the REVISION of the existing API"
        exit 1
    fi

    # check current REVISION and perform the applicable restore
    if [ "$1" -ge 40000 ]; then
        restore_old_api_4x
    fi

    # remove the old api backup
    rm -rf "${API_PATH_BACKUP}"
}



restore_old_api_4x() {

    # create configuration folder if it does not exists in the new api
    if [ ! -d "${API_PATH}"/configuration ]; then
        install -o root -g ossec -m 0770 -d "${API_PATH}"/configuration
    fi

    # create security folder if it does not exists in the new api
    if [ ! -d "${API_PATH}"/configuration/security ]; then
        install -o root -g ossec -m 0770 -d "${API_PATH}"/configuration/security
    fi

    # create ssl folder if it does not exists in the new api
    if [ ! -d "${API_PATH}"/configuration/ssl ]; then
        install -o root -g ossec -m 0770 -d "${API_PATH}"/configuration/ssl
    fi

    # Copy API yaml if exists
    if [ -e "${API_PATH_BACKUP}"/configuration/api.yaml ]; then
        cp -rLfp "${API_PATH_BACKUP}"/configuration/api.yaml "${API_PATH}"/configuration/
    fi

    # Copy security folder if exists and its not empty
    if [ -d "${API_PATH_BACKUP}"/configuration/security ]; then
        if [ -n "$(ls -A "${API_PATH_BACKUP}"/configuration/security)" ]; then
            cp -rLfp "${API_PATH_BACKUP}"/configuration/security/* "${API_PATH}"/configuration/security
        fi
    fi

    # Copy ssl folder if exists and its not empty
    if [ -d "${API_PATH_BACKUP}"/configuration/ssl ]; then
        if [ -n "$(ls -A "${API_PATH_BACKUP}"/configuration/ssl)" ]; then
            cp -rLfp "${API_PATH_BACKUP}"/configuration/ssl/* "${API_PATH}"/configuration/ssl
        fi
    fi
}