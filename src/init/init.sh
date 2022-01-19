#!/bin/sh

# Init functions for Wazuh
# Copyright (C) 2015, Wazuh Inc.
# Author: Daniel B. Cid <daniel.cid@gmail.com>

UN=${NUNAME};
service="wazuh";

runInit()
{
    echo ""
    echo ""

    if [ -n "$1" ]; then
        if [ "X$1" = "Xserver" ]; then
            service="$service-manager"
        else
            service="$service-$1"
        fi
    fi

    update_only=$2

    # Checking for Systemd
    if hash ps 2>&1 > /dev/null && hash grep 2>&1 > /dev/null && [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        if [ "X$1" = "Xserver" ] || [ "X$1" = "Xlocal" ]; then
            type=manager
        else
            type=agent
        fi
        # RHEL 8 services must to be installed in /usr/lib/systemd/system/
        if [ "${DIST_NAME}" = "rhel" -a "${DIST_VER}" -ge "7" ] || [ "${DIST_NAME}" = "centos" -a "${DIST_VER}" -ge "7" ]; then
            SERVICE_UNIT_PATH=/usr/lib/systemd/system/wazuh-$type.service
            rm -f /etc/systemd/system/wazuh-$type.service
        else
            SERVICE_UNIT_PATH=/etc/systemd/system/wazuh-$type.service
        fi
        GenerateService wazuh-$type.service > ${SERVICE_UNIT_PATH}
        chown root:wazuh ${SERVICE_UNIT_PATH}
        systemctl daemon-reload

        rm -f /etc/rc.d/init.d/${service}

        if [ "X${update_only}" = "X" ]
        then
            systemctl enable "wazuh-"$type
        fi

        return 0;
    fi

    # Checking if it is a Redhat system.
    if [ -r "/etc/redhat-release" ]; then
        if [ -d /etc/rc.d/init.d ]; then
            echo " - ${systemis} Redhat Linux."
            echo " - ${modifiedinit}"
            GenerateService ossec-hids-rh.init > /etc/rc.d/init.d/${service}
            chmod 755 /etc/rc.d/init.d/${service}
            chown root:wazuh /etc/rc.d/init.d/${service}

            if [ "X${update_only}" = "X" ]
            then
                /sbin/chkconfig --add ${service} > /dev/null 2>&1
            fi

            return 0;
        fi
    fi
    # Checking for Gentoo
    if [ -r "/etc/gentoo-release" ]; then
        echo " - ${systemis} Gentoo Linux."
        echo " - ${modifiedinit}"
        GenerateService ossec-hids-gentoo.init > /etc/init.d/${service}
        chmod 755 /etc/init.d/${service}
        chown root:wazuh /etc/init.d/${service}

        if [ "X${update_only}" = "X" ]
        then
            rc-update add ${service} default
        fi

        return 0;
    fi

    # Suse
    if [ -r "/etc/SuSE-release" ]; then
        echo " - ${systemis} Suse Linux."
        echo " - ${modifiedinit}"
        GenerateService ossec-hids-suse.init > /etc/init.d/${service}
        chmod 755 /etc/init.d/${service}
        chown root:wazuh /etc/init.d/${service}

        if [ "X${update_only}" = "X" ]
        then
            /sbin/chkconfig --add ${service} > /dev/null 2>&1
        fi

        return 0;
    fi

    # Checking for slackware (by Jack S. Lai)
    if [ -r "/etc/slackware-version" ]; then
        echo " - ${systemis} Slackware Linux."
        echo " - ${modifiedinit}"
        GenerateService ossec-hids.init > /etc/rc.d/rc.${service}
        chmod 755 /etc/rc.d/rc.${service}
        chown root:wazuh /etc/rc.d/rc.${service}

        grep ${service} /etc/rc.d/rc.local > /dev/null 2>&1
        if [ $? != 0 ]; then
            echo "if [ -x /etc/rc.d/rc.${service} ]; then" >> /etc/rc.d/rc.local
            echo "      /etc/rc.d/rc.${service} start" >>/etc/rc.d/rc.local
            echo "fi" >>/etc/rc.d/rc.local
        fi

        return 0;
    fi

    # Darwin init script (by Lorenzo Costanzia di Costigliole <mummie@tin.it>)
    if [ "X${NUNAME}" = "XDarwin" ]; then
        # Generating darwin init script.

        echo " - ${systemis} Darwin."
        echo " - ${modifiedinit}"
        sh ./src/init/darwin-init.sh ${INSTALLDIR}
        return 0;
    fi

    if [ "X${UN}" = "XSunOS" ]; then
        echo " - ${systemis} Solaris (SunOS)."
        echo " - ${modifiedinit}"
        GenerateService ossec-hids-solaris.init > /etc/init.d/${service}
        chmod 755 /etc/init.d/${service}

        if [ "X${update_only}" = "X" ]
        then
            ln -s /etc/init.d/${service} /etc/rc2.d/S97${service}
            ln -s /etc/init.d/${service} /etc/rc3.d/S97${service}
        fi

        return 0;
    fi

    if [ "X${UN}" = "XHP-UX" ]; then
        echo " - ${systemis} HP-UX."
        echo " - ${modifiedinit}"
        GenerateService ossec-hids-hpux.init > /sbin/init.d/${service}
        chmod 755 /sbin/init.d/${service}

        if [ "X${update_only}" = "X" ]
        then
            ln -s /sbin/init.d/${service} /sbin/rc2.d/S97${service}
            ln -s /sbin/init.d/${service} /sbin/rc3.d/S97${service}
        fi

        return 0;
    fi

    if [ "X${UN}" = "XAIX" ]; then
        echo " - ${systemis} AIX."
        echo " - ${modifiedinit}"
        GenerateService ossec-hids-aix.init > /etc/rc.d/init.d/${service}
        chmod 755 /etc/rc.d/init.d/${service}

        if [ "X${update_only}" = "X" ]
        then
            ln -s /etc/rc.d/init.d/${service} /etc/rc.d/rc2.d/S97${service}
            ln -s /etc/rc.d/init.d/${service} /etc/rc.d/rc3.d/S97${service}
        fi

        return 0;
    fi

    if [ "X${UN}" = "XOpenBSD" -o "X${UN}" = "XNetBSD" -o "X${UN}" = "XFreeBSD" -o "X${UN}" = "XDragonFly" ]; then
        # Checking for the presence of wazuh-control on rc.local
        grep wazuh-control /etc/rc.local > /dev/null 2>&1
        if [ $? != 0 ]; then
            echo "echo \"${starting}\"" >> /etc/rc.local
            echo "${INSTALLDIR}/bin/wazuh-control start" >> /etc/rc.local
        fi
        echo " - ${systemis} ${NUNAME}."
        echo " - ${modifiedinit}"
        return 0;
    elif [ "X${NUNAME}" = "XLinux" ]; then
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
            GenerateService ossec-hids.init > /etc/rc.d/init.d/${service}
            chmod 755 /etc/rc.d/init.d/${service}
            chown root:wazuh /etc/rc.d/init.d/${service}
            return 0;
        # Taken from Stephen Bunn ossec howto.
        elif [ -d "/etc/init.d" -a -f "/usr/sbin/update-rc.d" ]; then
            echo " - ${systemis} Debian (Ubuntu or derivative)."
            echo " - ${modifiedinit}"
            GenerateService ossec-hids-debian.init > /etc/init.d/${service}
            chmod +x /etc/init.d/${service}
            chmod go-w /etc/init.d/${service}
            chown root:wazuh /etc/init.d/${service}

            if [ "X${update_only}" = "X" ]
            then
                update-rc.d ${service} defaults > /dev/null 2>&1
            fi

            return 0;
        else
            echo " - ${noboot}"
        fi
    else
        echo " - ${noboot}"
    fi

    return 1;
}
