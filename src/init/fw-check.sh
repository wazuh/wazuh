#!/bin/sh


# Checking which firewall to use.
UNAME=`uname`
FILE="";
EXECUTE="$1";

if [ "X${UNAME}" = "XFreeBSD" ]; then
    # Is ipfw enabled?
    grep 'firewall_enable="YES"' /etc/rc.conf >/dev/null 2>&1
    if [ $? = 0 ]; then
        # Firewall is IPFW
        FILE="ipfw.sh";
        echo "IPFW";
    fi    

    # if pf enabled?
    grep 'pf_enable="YES"' /etc/rc.conf >/dev/null 2>&1
    if [ $? = 0 ]; then
        # Firewall is PF
        FILE="pf.sh";
        echo "PF";
    fi    

# Darwin
elif [ "X${UNAME}" = "XDarwin" ]; then
    # Is pfctl present?
    which pfctl;
    if [ $? = 0 ]; then
        echo "PF";
        FIlE="pf.sh";
    else
        echo "IPFW";
        FILE="ipfw_mac.sh";
    fi
        
elif [ "X${UNAME}" = "XOpenBSD" ]; then
    if [ $? = 0 ]; then
        # Firewall is PF
        FILE="pf.sh";
        echo "PF";
    fi    
fi


# If file is set and execute flag is set
if [ ! "X$FILE" = "X" ]; then
    if [ "X$EXECUTE" = "Xexecute" ]; then
        cp -pr ../active-response/firewall-drop.sh ../active-response/firewalls/default-firewall-drop.sh
        cp -pr ../active-response/firewalls/$FILE ../active-response/firewall-drop.sh
    fi
fi    

exit 0;    
