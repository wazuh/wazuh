#!/bin/sh
# Init functions for the OSSEC HIDS
# Author: Daniel B. Cid <daniel.cid@gmail.com>
# Last modification: Mar 03, 2006

UN=${NUNAME};

runInit()
{
    echo ""
    echo ""
    if [ "X${UN}" = "XOpenBSD" -o "X${UN}" = "XNetBSD" -o "X${UN}" = "XFreeBSD" ]; then
        # Checking for the presence of ossec-control on rc.local
        grep ossec-control /etc/rc.local > /dev/null 2>&1
        if [ $? != 0 ]; then
            echo "echo \"${starting}\"" >> /etc/rc.local
            echo "${INSTALLDIR}/bin/ossec-control start" >> /etc/rc.local
        fi
        echo " - ${systemis} ${NUNAME}."
        echo " - ${modifiedinit}"
        return 0;
    elif [ "X${NUNAME}" = "XLinux" ]; then
        if [ -d "/etc/rc.d/init.d" ]; then
            echo " - ${systemis} Linux (SysV)."
            echo " - ${modifiedinit}"
            cp -pr ./src/init/ossec-hids.init  /etc/rc.d/init.d/ossec
            return 0;
        elif [ -e "/etc/rc.d/rc.local" ]; then
            echo " - ${systemis} Linux."
            echo " - ${modifiedinit}"
            echo "echo \"${starting}\"" >> /etc/rc.d/rc.local
            echo "${INSTALLDIR}/bin/ossec-control start" >> /etc/rc.d/rc.local
            return 0;
        else
            echo " - ${noboot}"
        fi        
    else
        echo " - ${noboot}"
    fi
    
    return 1;        
}


# EOF 
