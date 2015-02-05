#!/bin/sh

# Agentless monitoring
#
# Copyright (C) 2009 Trend Micro Inc.
# All rights reserved.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

MYNAME="register_host.sh"
MYPASS=".passlist"

# Check the location
ls -la $MYNAME > /dev/null 2>&1
if [ ! $? = 0 ]; then
    LOCALDIR=`dirname $0`;
    cd ${LOCALDIR}

    ls -la $MYNAME > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        echo "ERROR: You must run this script from the same directory."
        exit 1;
    fi
fi

# Arguments
if [ "x$1" = "x" -o "x$1" = "xhelp" -o "x$1" = "x-h" ]; then
    echo "$0 options:"
    echo "        add <user@host> [<passwd>] (<additional_pass>)"
    echo "        list (passwords)"
    exit 0;
fi

if [ "x$1" = "xlist" ]; then
    echo "*Available hosts: "
    if [ "x$2" = "xpasswords" ]; then
        cat $MYPASS | sort | uniq;
    else
        cat $MYPASS | cut -d "|" -f 1 | sort | uniq;
    fi
    exit 0;

elif [ "x$1" = "xadd" ]; then
    if [ "x$2" = "x" ]; then
        echo "ERROR: Missing hostname name.";
        echo "ex: $0 add <user@host> [<passwd>] (<additional_pass>)";
        exit 1;
    fi

    grep "$2|" $MYPASS > /dev/null 2>&1
    if [ $? = 0 ]; then
        echo "ERROR: Host '$2' already added.";
        exit 1;
    fi

    # Check if the password was supplied
    if [ "x$3" = "x" ]; then
        echo "Please provide password for host $2."
        echo -n "Password: ";
        stty -echo
        read INPASS
        stty echo

        echo "Please provide additional password for host $2 (<enter> for empty)."
        echo -n "Password: ";
        stty -echo
        read ADDPASS
        stty echo
    else
        INPASS=$3
        ADDPASS=$4
    fi

    echo "$2|$INPASS|$ADDPASS" >> $MYPASS;
    if [ ! $? = 0 ]; then
        echo "ERROR: Unable to creating entry (echo failed)."
        exit 1;
    fi
    chmod 744 $MYPASS
    echo "*Host $2 added."

else
    echo "ERROR: Invalid argument.";
    exit 1;

fi

