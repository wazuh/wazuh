#!/bin/sh

# Wazuh Distribution Detector
# Copyright (C) 2015, Wazuh Inc.
# November 18, 2016.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Default values
DIST_NAME="Linux"
DIST_VER="0"
DIST_SUBVER="0"

if [ -r "/etc/os-release" ]; then
    . /etc/os-release
    DIST_NAME=$ID
    DIST_VER=$(echo $VERSION_ID | sed -rn 's/[^0-9]*([0-9]+).*/\1/p')
    if [ "X$DIST_VER" = "X" ]; then
        DIST_VER="0"
    fi
    if [ "$DIST_NAME" = "amzn" ] && [ "$DIST_VER" = "2018" ]; then
        DIST_VER="1"
    fi
    DIST_SUBVER=$(echo $VERSION_ID | sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p')
    if [ "X$DIST_SUBVER" = "X" ]; then
        DIST_SUBVER="0"
    fi
fi

if [ ! -r "/etc/os-release" ] || [ "$DIST_NAME" = "centos" ]; then
    # CentOS
    if [ -r "/etc/centos-release" ]; then
        DIST_NAME="centos"
        DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/centos-release`
        DIST_SUBVER=`sed -rn 's/.* [0-9]{1,2}\.*([0-9]{0,2}).*/\1/p' /etc/centos-release`

    # RedHat
    elif [ -r "/etc/redhat-release" ]; then
        if grep -q "CentOS" /etc/redhat-release; then
            DIST_NAME="centos"
        else
            DIST_NAME="rhel"
        fi
        DIST_VER=`sed -rn 's/.* ([0-9]{1,2})\.*[0-9]{0,2}.*/\1/p' /etc/redhat-release`
        DIST_SUBVER=`sed -rn 's/.* [0-9]{1,2}\.*([0-9]{0,2}).*/\1/p' /etc/redhat-release`

    # Ubuntu
    elif [ -r "/etc/lsb-release" ]; then
        . /etc/lsb-release
        DIST_NAME="ubuntu"
        DIST_VER=$(echo $DISTRIB_RELEASE | sed -rn 's/.*([0-9][0-9])\.[0-9][0-9].*/\1/p')
        DIST_SUBVER=$(echo $DISTRIB_RELEASE | sed -rn 's/.*[0-9][0-9]\.([0-9][0-9]).*/\1/p')

    # Debian
    elif [ -r "/etc/debian_version" ]; then
        DIST_NAME="debian"
        DIST_VER=`sed -rn 's/[^0-9]*([0-9]+).*/\1/p' /etc/debian_version`
        DIST_SUBVER=`sed -rn 's/[^0-9]*[0-9]+\.([0-9]+).*/\1/p' /etc/debian_version`

    # Amazon Linux 2, 2023
    elif [ -r "/etc/system-release" ]; then
        if grep -q "Amazon Linux release" /etc/system-release; then
            DIST_NAME="amzn"
            DIST_VER_FULL=`sed -rn 's/.*release ([0-9]+(\.[0-9]+)?).*/\1/p' /etc/system-release`
            DIST_VER=`echo $DIST_VER_FULL | cut -d. -f1`
            DIST_SUBVER=`echo $DIST_VER_FULL | cut -d. -f2`
        fi
    elif [ "X$(uname)" = "XLinux" ]; then
        DIST_NAME="Linux"

    fi
    if [ "X$DIST_SUBVER" = "X" ]; then
        DIST_SUBVER="0"
    fi
fi
