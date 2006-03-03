#!/bin/sh
# Shell script functions for the OSSEC HIDS
# Author: Daniel B. Cid <daniel.cid@gmail.com>
# Last modification: Mar 02, 2006


TRUE="true";
FALSE="false";


##########
# isFile
##########
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


