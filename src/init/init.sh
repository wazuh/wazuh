#!/bin/sh

# Init functions for Wazuh
# Copyright (C) 2015, Wazuh Inc.
# Author: Daniel B. Cid <daniel.cid@gmail.com>

UN=${NUNAME};
service="wazuh-server";

runInit()
{
    echo ""
    echo ""

    # Checking for Systemd
    if hash ps 2>&1 > /dev/null && hash grep 2>&1 > /dev/null && [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        # RHEL 8 services must to be installed in /usr/lib/systemd/system/
        if [ "${DIST_NAME}" = "rhel" -a "${DIST_VER}" -ge "7" ] || [ "${DIST_NAME}" = "centos" -a "${DIST_VER}" -ge "7" ]; then
            SERVICE_UNIT_PATH=/usr/lib/systemd/system/wazuh-server.service
            rm -f /etc/systemd/system/wazuh-server.service
        else
            SERVICE_UNIT_PATH=/etc/systemd/system/wazuh-server.service
        fi
        GenerateService wazuh-server.service > ${SERVICE_UNIT_PATH}
        chown root:wazuh ${SERVICE_UNIT_PATH}
        systemctl daemon-reload

        rm -f /etc/rc.d/init.d/${service}

        return 0;
    fi

    # Checking if it is a Redhat system.
    if [ -r "/etc/redhat-release" ]; then
        if [ -d /etc/rc.d/init.d ]; then
            echo " - ${systemis} Redhat Linux."
            echo " - ${modifiedinit}"
            GenerateService wazuh-server-rh.init > /etc/rc.d/init.d/${service}
            chmod 755 /etc/rc.d/init.d/${service}
            chown root:wazuh /etc/rc.d/init.d/${service}

            return 0;
        fi
    fi

    if [ "X${NUNAME}" = "XLinux" ]; then
        if [ -e "/etc/rc.d/rc.local" ]; then
            echo " - ${systemis} Linux."
            echo " - ${modifiedinit}"

            grep wazuh-control /etc/rc.d/rc.local > /dev/null 2>&1
            if [ $? != 0 ]; then
                echo "echo \"${starting}\"" >> /etc/rc.d/rc.local
                echo "${INSTALLDIR}/bin/wazuh-control start" >> /etc/rc.d/rc.local
            fi
            return 0;
        elif [ -d "/etc/rc.d/init.d" ]; then
            echo " - ${systemis} Linux (SysV)."
            echo " - ${modifiedinit}"
            GenerateService wazuh-server.init > /etc/rc.d/init.d/${service}
            chmod 755 /etc/rc.d/init.d/${service}
            chown root:wazuh /etc/rc.d/init.d/${service}
            return 0;
        # Taken from Stephen Bunn ossec howto.
        elif [ -d "/etc/init.d" -a -f "/usr/sbin/update-rc.d" ]; then
            echo " - ${systemis} Debian (Ubuntu or derivative)."
            echo " - ${modifiedinit}"
            GenerateService wazuh-server-debian.init > /etc/init.d/${service}
            chmod +x /etc/init.d/${service}
            chmod go-w /etc/init.d/${service}
            chown root:wazuh /etc/init.d/${service}

            return 0;
        else
            echo " - ${noboot}"
        fi
    else
        echo " - ${noboot}"
    fi

    return 1;
}
