#!/bin/sh
#Active response script for OPNSense platform (should work with pfSense too)
# should be in <OSSEC_PATH>/active-response/bin/opnsense.sh
#TrustUX Network 20160803 by JCC
#Block the offensor IP in the virusprot table - default in pfSense's/OPNSense's 
#ref.: https://doc.pfsense.org/index.php/Virusprot
#Tested on OPNSense 16.7 and pfSense 2.2.x

#VARs
PFCTL_CMD="/sbin/pfctl"
PF_TABLE="virusprot"
ACTION=$1
USER=$2
IP=$3


#CHECK IF THIS IS THE RIGHT OS
CHK_TABLE=$(pfctl -sT | grep virusprot)
OS=$(uname)

if [ "$CHK_TABLE" == "virusprot" ] && [ "$OS" == "FreeBSD" ];then
        echo "OK"
else
        echo "This OS don't seems to be a pfSense or OPNSense firewall... exiting"
        exit 1
fi

#GET BASE OSSEC INSTALLATION PATH
BASE=$(ps fax | awk '{print $5}' | grep ossec-execd | grep -v grep | sed 's/\/bin\/ossec-execd//g')
LOG_PATH="$BASE/logs"


#CHECK IF PARAMS ARE OK
if [ -z "$ACTION" ] || [ -z "$IP" ];then
    echo "ERROR: usage $0: <action> <username> <ip>" 
    exit 1
fi

#LETS BLOCK!
case $ACTION in
    "add")
        echo "$(date) $0 $1 $2 $3" >> $LOG_PATH/active-responses.log
        $PFCTL_CMD -t $PF_TABLE -T add $IP > /dev/null 2>&1
    ;;
    "delete")
        echo "$(date) $0 $1 $2 $3" >> $LOG_PATH/active-responses.log
        $PFCTL_CMD -t $PF_TABLE -T delete $IP > /dev/null 2>&1
    ;;
    *)
        echo "$0 ERROR: unknow action: $ACTION"
    ;;
esac

