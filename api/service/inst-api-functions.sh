#!/bin/sh

# Wazuh API Installer Functions
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.




backup_old_api() {

    API_PATH=${PREFIX}/api
    API_PATH_BACKUP=${PREFIX}/~api

    # do backup only if config.js file exists
    if [ -f ${API_PATH}/configuration/config.js ]; then

        # remove backup folder and its contents if exists
        if [ -e ${API_PATH_BACKUP} ]; then
            rm -rf ${API_PATH_BACKUP}
        fi

        install -o root -g ossec -m 0770 -d ${API_PATH_BACKUP}
        install -o root -g ossec -m 0770 -d ${API_PATH_BACKUP}/configuration

        cp -rLfp ${API_PATH}/configuration/config.js ${API_PATH_BACKUP}/configuration/config.js

        # copy ssl contents if the folder exists
        if [ -d ${API_PATH}/configuration/ssl ]; then
            install -o root -g ossec -m 0770 -d ${API_PATH_BACKUP}/configuration/ssl
            cp -rLfp ${API_PATH}/configuration/ssl/* ${API_PATH_BACKUP}/configuration/ssl
        fi

        # remove old API directory
        rm -rf ${API_PATH}

    fi

}

restore_old_api() {

    API_PATH=${PREFIX}/api
    API_PATH_BACKUP=${PREFIX}/~api

    # perform migration only if there is config.js file in the old api backup
    if [ -r ${API_PATH_BACKUP}/configuration/config.js ]; then

        # execute migration.py
        ${PREFIX}/framework/python/bin/python3 ../api/scripts/migration.py

        # create ssl folder if it does not exists in the new api
        if [ ! -d ${API_PATH}/configuration/ssl ]; then
            install -o root -g ossec -m 0770 -d ${API_PATH}/configuration/ssl
        fi

        # if the ssl folder exists in the api backup copy its content to new api's ssl folder
        if [ -d ${API_PATH_BACKUP}/configuration/ssl ]; then
            cp -rLfp ${API_PATH_BACKUP}/configuration/ssl/* ${API_PATH}/configuration/ssl
        fi

        # remove the old api backup
        rm -rf ${API_PATH_BACKUP}
    fi
}
