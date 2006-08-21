#!/bin/sh
# Init functions for the OSSEC HIDS
# v0.3
# Author: Daniel B. Cid <daniel.cid@gmail.com>
# Last modification: May 04, 2006 (by Kayvan A. Sylvan <kayvan@sylvan.com>)
# v0,2: Mar 03, 2006
# v0.1: Jan 01, 2005

UN=${NUNAME};

runInit()
{
    echo ""
    echo ""
    # Checking if it is a Redhat system.
    if [ -r "/etc/redhat-release" ]; then
        if [ -d /etc/rc.d/init.d ]; then
            echo " - ${systemis} Redhat Linux."
            echo " - ${modifiedinit}"
            cp -pr ./src/init/ossec-hids-rh.init /etc/rc.d/init.d/ossec
            chmod 555 /etc/rc.d/init.d/ossec
            chown root:ossec /etc/rc.d/init.d/ossec
            /sbin/chkconfig --add ossec
            return 0;
        fi
    fi
    # Checking for Gentoo
    if [ -r "/etc/gentoo-release" ]; then
        echo " - ${systemis} Gentoo Linux."
        echo " - ${modifiedinit}"
        cp -pr ./src/init/ossec-hids-gentoo.init /etc/init.d/ossec
        chmod 555 /etc/init.d/ossec
        chown root:ossec /etc/init.d/ossec
        rc-update add ossec default
        return 0;
    fi    
    
    # Darwin init script (by Lorenzo Costanzia di Costigliole <mummie@tin.it>)
    if [ "X${NUNAME}" = "Darwin" ]; then
        # Generating darwin init script.

        echo " - ${systemis} Darwin."
        echo " - ${modifiedinit}"
        sh ./src/init/darwin-init.sh
        return 0;
    fi
         
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
        if [ -e "/etc/rc.d/rc.local" ]; then
            echo " - ${systemis} Linux."
            echo " - ${modifiedinit}"

            grep ossec-control /etc/rc.d/rc.local > /dev/null 2>&1
            if [ $? != 0 ]; then
                echo "echo \"${starting}\"" >> /etc/rc.d/rc.local
                echo "${INSTALLDIR}/bin/ossec-control start" >> /etc/rc.d/rc.local
            fi
            return 0;
        elif [ -d "/etc/rc.d/init.d" ]; then
            echo " - ${systemis} Linux (SysV)."
            echo " - ${modifiedinit}"
            cp -pr ./src/init/ossec-hids.init  /etc/rc.d/init.d/ossec
            chmod 555 /etc/rc.d/init.d/ossec
            chown root:ossec /etc/rc.d/init.d/ossec
            return 0;
        # Taken from Stephen Bunn ossec howto.    
        elif [ -d "/etc/init.d" -a -f "/usr/sbin/update-rc.d" ]; then
            echo " - ${systemis} Ubuntu Linux."
            echo " - ${modifiedinit}"
            cp -pr ./src/init/ossec-hids.init  /etc/init.d/ossec
            chmod +x /etc/init.d/ossec
            chmod go-w /etc/init.d/ossec
            chown root:ossec /etc/init.d/ossec
            update-rc.d ossec defaults
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
