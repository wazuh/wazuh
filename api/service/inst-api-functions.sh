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

        if [ -e ${API_PATH_BACKUP} ]; then
            rm -rf ${API_PATH_BACKUP}
        else
            ${INSTALL} -d -m 0770 -o root -g ${OSSEC_GROUP} ${API_PATH_BACKUP}
            chown root:ossec ${API_PATH_BACKUP}
        fi

        ${INSTALL} -d -m 0770 -o root -g ${OSSEC_GROUP} ${API_PATH_BACKUP}/configuration
        cp -rLfp ${API_PATH}/configuration/config.js ${API_PATH_BACKUP}/configuration/config.js

        if [ -d ${API_PATH}/configuration/ssl ]; then
            ${INSTALL} -d -m 0770 -o root -g ${OSSEC_GROUP} ${API_PATH_BACKUP}/configuration/ssl
            cp -rLfp ${API_PATH}/configuration/ssl/* ${API_PATH_BACKUP}/configuration/ssl
        fi

        # remove old API directory
        rm -rf ${API_PATH}

    fi

}

restore_old_api() {

    API_PATH=${PREFIX}/api
    API_PATH_BACKUP=${PREFIX}/~api

    if [ -r ${API_PATH_BACKUP}/configuration/config.js ]; then
        # execute migration.py
        ${PREFIX}/framework/python/bin/python3 ../api/migration.py
        if [ ! -d ${API_PATH}/configuration/ssl ]; then
            ${INSTALL} -d -m 0770 -o root -g ${OSSEC_GROUP} ${API_PATH}/configuration/ssl
        fi
        cp -rLfp ${API_PATH_BACKUP}/configuration/ssl/* ${API_PATH}/configuration/ssl
        rm -rf ${API_PATH_BACKUP}
    fi
}
