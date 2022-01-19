#!/bin/sh

# Copyright (C) 2015, Wazuh Inc.

set -e
set -u

# Checking which firewall to use.
UNAME=$(uname);
FILE="default-firewall-drop";

if [ "X${UNAME}" = "XFreeBSD" ]; then
    if grep -i 'pf_enable="YES"' /etc/rc.conf >/dev/null 2>&1; then
        FILE="pf";
        echo "PF";
    elif grep -i 'firewall_enable="YES"' /etc/rc.conf >/dev/null 2>&1; then
        FILE="ipfw";
        echo "IPFW";
    fi
elif [ "X${UNAME}" = "XOpenBSD" ]; then
    if grep -i 'pf_enable="YES"' /etc/rc.conf >/dev/null 2>&1; then
        FILE="pf";
        echo "PF";
    fi
elif [ "X${UNAME}" = "XDarwin" ]; then
    if which pfctl > /dev/null; then
        FILE="pf";
        echo "PF";
    fi
fi

# If file is set and execute flag is set
if [ ! "X$FILE" = "X" ]; then
    if [ $# -eq 1 ] && [ "X$1" = "Xexecute" ]; then
        cp -pr $FILE firewall-drop
    fi
fi

exit 0;
