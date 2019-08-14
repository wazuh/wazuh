#!/bin/sh
# language.sh
# Copyright (C) 2015-2019, Wazuh Inc.
# Author: Daniel B. Cid <daniel.cid@gmail.com>

catError()
{
    FILE=$1;

    FILE_PATH="${TEMPLATE}/${LANGUAGE}/${ERROR}/${FILE}.txt"
    if [ `isFile ${FILE_PATH}` = "${FALSE}" ]; then
        # If we can't file in that specific language, try
        # the english one.
        FILE_PATH="${TEMPLATE}/en/${ERROR}/${FILE}.txt"
        if [ `isFile ${FILE_PATH}` = "${FALSE}" ]; then
            echo "0x0000 - Internal error for ${FILE}"
            exit 1;
        fi
    fi
    cat ${FILE_PATH}
    exit 1;
}

catMsg()
{
    FILE=$1;

    FILE_PATH="${TEMPLATE}/${LANGUAGE}/${MSG}/${FILE}.txt"
    if [ `isFile ${FILE_PATH}` = "${FALSE}" ]; then
        # If we can't file in that specific language, try
        # the english one.
        FILE_PATH="${TEMPLATE}/en/${MSG}/${FILE}.txt"
        FILE_PATH="${MSG_TEMPLATE}/en/${FILE}.txt"
        if [ `isFile ${FILE_PATH}` = "${FALSE}" ]; then
            echo "0x0001 - Internal error for ${FILE}"
            exit 1;
        fi
    fi

    cat ${FILE_PATH}
}

