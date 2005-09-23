#!/bin/sh

PWD=`pwd | grep init`
LOC=""
if [ "X${PWD}" != "X" ]; then
	cd ../
fi

LOCATION="${LOC}LOCATION" 
UNAME=`uname`
DEFAULT_DIR=`grep DIR ${LOCATION} | cut -f2 -d\"`



# Generating the INIT script (based on the system)
echo ""
echo ""
echo " --- RESULTS START HERE ---  "
echo ""

if [ "X${UNAME}" = "XOpenBSD" ] || [ "X${UNAME}" = "XNetBSD" ] || [ "X${UNAME}" = "XFreeBSD" ]; then
    grep ossec-control /etc/rc.local > /dev/null 2>&1
    if [ $? != 0 ]; then
	 echo " - System is ${UNAME}, modified /etc/rc.local to start OSSEC HIDS"
	 echo "echo \"Starting OSSEC HIDS\"" >> /etc/rc.local
	 echo "${DEFAULT_DIR}/bin/ossec-control start" >> /etc/rc.local
    fi

elif [ "X${UNAME}" = "XLinux" ]; then
	if [ -d "/etc/rc.d/init.d" ]; then
		echo " - System is Linux (SysV based)."
		echo " - Added /etc/rc.d/init.d/ossec to control OSSEC HIDS"
		cp -pr ${LOC}init/ossec-hids.init  /etc/rc.d/init.d/ossec
	elif [ -e "/etc/rc.d/rc.local" ]; then
        grep ossec-control /etc/rc.d/rc.local > /dev/null 2>&1
        if [ $? != 0 ]; then
    	 echo " - System is Linux." 
		 echo " - Modified /etc/rc.d/rc.local to start OSSEC HIDS"
		 echo "echo \"Starting OSSEC HIDS\"" >> /etc/rc.d/rc.local
		 echo "${DEFAULT_DIR}/bin/ossec-control start" >> /etc/rc.d/rc.local
        fi 
	else
		echo " - Unkown Linux system. No init script added."
	fi
else
	echo " - Unkown system. No init script added."
fi

# EOF 
