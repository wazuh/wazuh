#!/bin/sh

# Checking which firewall to use.
UNAME=`uname`

if [ "X${UNAME}" = "XFreeBSD" ]; then
    
    # Is ipfw enabled?
    grep 'firewall_enable="YES"' /etc/rc.conf >/dev/null 2>&1
    if [ $? = 0 ]; then
        # Firewall is IPFW
        cp -pr ../active-response/firewalls/ipfw.sh ../active-response/firewall-drop.sh
    fi    

    exit 0;
fi

exit 0;    
