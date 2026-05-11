#!/bin/sh

# Wazuh API Installer Functions
# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


API_PATH=${INSTALLDIR}/api
API_PATH_BACKUP=${INSTALLDIR}/~api
WAZUH_GROUP="${WAZUH_GROUP:-wazuh}"



backup_old_api() {

    # Remove backup folder and its contents if exists
    if [ -e "${API_PATH_BACKUP}" ]; then
        rm -rf "${API_PATH_BACKUP}"
    fi

    # Wazuh 5.x only preserves the current API configuration layout.
    if [ -d "${API_PATH}/configuration" ] && [ -n "$(ls -A "${API_PATH}/configuration")" ]; then
        install -o root -g ${WAZUH_GROUP} -m 0770 -d "${API_PATH_BACKUP}"
        cp -rLfp "${API_PATH}/configuration" "${API_PATH_BACKUP}/"
    else
        echo "No API configuration found to back up."
    fi

    # Remove old API directory
    rm -rf "${API_PATH}"
}



restore_old_api() {
    if [ -d "${API_PATH_BACKUP}/configuration" ]; then
        install -o root -g ${WAZUH_GROUP} -m 0770 -d "${API_PATH}/configuration"
        cp -rLfp "${API_PATH_BACKUP}/configuration/." "${API_PATH}/configuration/"
    else
        echo "No API configuration backup found to restore."
    fi

    # Remove the old api backup
    rm -rf "${API_PATH_BACKUP}"
}
