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
OSSEC_GROUP="ossec"
WAZUH_GROUP="wazuh"
4_2_REVISION=40200
4_X_REVISION=40000



stop_api_3x(){
    # Stop api process if its still running
    OLD_API_PID=$(pgrep -f "${API_PATH}/app.js")
    if [ -n "$OLD_API_PID" ]; then
        echo "killing old api process: ${OLD_API_PID}"
        kill -9 "${OLD_API_PID}"
    fi
}



backup_old_api() {

    if [ $# -ne 1 ]; then
        echo "Backup_old_api requires the REVISION of the existing API"
        exit 1
    fi

    # Remove backup folder and its contents if exists
    if [ -e "${API_PATH_BACKUP}" ]; then
        rm -rf "${API_PATH_BACKUP}"
    fi

    # Check current REVISION and perform the applicable backup
    if [ "$1" -ge ${4_2_REVISION} ]; then
        backup_old_api_4x ${WAZUH_GROUP}
    elif [ "$1" -ge ${4_X_REVISION} ]; then
        backup_old_api_4x ${OSSEC_GROUP}
    else
        stop_api_3x
    fi

    # Remove old API directory
    rm -rf "${API_PATH}"
}



backup_old_api_4x() {

    if [ $# -ne 1 ]; then
        echo "backup_old_api_4x requires an argument indicating the group name"
        exit 1
    fi

    # Backup files only if configuration folder exists and its not empty
    if [ -d "${API_PATH}"/configuration ]; then
        if [ -n "$(ls -A "${API_PATH}"/configuration)" ]; then

            install -o root -g $1 -m 0770 -d "${API_PATH_BACKUP}"/configuration

            # Backup API yaml if exists
            if [ -e "${API_PATH}"/configuration/api.yaml ]; then
                cp -rLfp "${API_PATH}"/configuration/api.yaml "${API_PATH_BACKUP}"/configuration/
            fi

            # Backup security files if the folder exists and its not empty
            if [ -d "${API_PATH}"/configuration/security ]; then
                if [ -n "$(ls -A "${API_PATH}"/configuration/security)" ]; then
                    install -o root -g $1 -m 0770 -d "${API_PATH_BACKUP}"/configuration/security
                    cp -rLfp "${API_PATH}"/configuration/security/* "${API_PATH_BACKUP}"/configuration/security
                fi
            fi

            # Backup ssl files if the folder exists and its not empty
            if [ -d "${API_PATH}"/configuration/ssl ]; then
                if [ -n "$(ls -A "${API_PATH}"/configuration/ssl)" ]; then
                    install -o root -g $1 -m 0770 -d "${API_PATH_BACKUP}"/configuration/ssl
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

    # Check current REVISION and perform the applicable restore
    if [ "$1" -ge ${4_2_REVISION} ]; then
        restore_old_api_4x ${WAZUH_GROUP}
    elif [ "$1" -ge ${4_X_REVISION} ]; then
        restore_old_api_4x ${OSSEC_GROUP}
    fi

    # Remove the old api backup
    rm -rf "${API_PATH_BACKUP}"
}



restore_old_api_4x() {

    if [ $# -ne 1 ]; then
        echo "restore_old_api_4x requires an argument indicating the group name"
        exit 1
    fi

    # Create configuration folder if it does not exists in the new api
    if [ ! -d "${API_PATH}"/configuration ]; then
        install -o root -g $1 -m 0770 -d "${API_PATH}"/configuration
    fi

    # Create security folder if it does not exists in the new api
    if [ ! -d "${API_PATH}"/configuration/security ]; then
        install -o root -g $1 -m 0770 -d "${API_PATH}"/configuration/security
    fi

    # Create ssl folder if it does not exists in the new api
    if [ ! -d "${API_PATH}"/configuration/ssl ]; then
        install -o root -g $1 -m 0770 -d "${API_PATH}"/configuration/ssl
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