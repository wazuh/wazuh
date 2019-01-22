#!/bin/sh

# Shell script functions for the OSSEC HIDS
# Copyright (C) 2015-2019, Wazuh Inc.
# Author: Daniel B. Cid <daniel.cid@gmail.com>

TRUE="true";
FALSE="false";


isFile()
{
    FILE=$1
    ls ${FILE} >/dev/null 2>&1
    if [ $? = 0 ]; then
        echo "${TRUE}"
        return 0;
    fi
    echo "${FALSE}"
    return 1;
}

