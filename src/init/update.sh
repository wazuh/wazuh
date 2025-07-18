#!/bin/sh

# Copyright (C) 2015, Wazuh Inc.
# Shell script update functions for Wazuh
# Author: Daniel B. Cid <daniel.cid@gmail.com>

FALSE="false"
TRUE="true"

doUpdatecleanup()
{
    if [ "X$INSTALLDIR" = "X" ]; then
        echo "# ($FUNCNAME) ERROR: The variable INSTALLDIR wasn't set." 1>&2
        echo "${FALSE}"
        return 1;
    fi

    # Checking if the directory is valid.
    _dir_pattern_update="^/[-a-zA-Z0-9/\.-]{3,128}$"
    echo $INSTALLDIR | grep -E "$_dir_pattern_update" > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        echo "# ($FUNCNAME) ERROR: directory name ($INSTALLDIR) doesn't match the pattern $_dir_pattern_update" 1>&2
        echo "${FALSE}"
        return 1;
    fi
}

##########
# Checks if Wazuh is installed by taking the installdir from the services
# files (if exists) and taking into account the installation type.
#
# getPreinstalledDirByType()
##########
getPreinstalledDirByType()
{
    # Checking for Systemd
    if hash ps 2>&1 > /dev/null && hash grep 2>&1 > /dev/null && [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then

        SED_EXTRACT_PREINSTALLEDDIR="s/^ExecStart=\/usr\/bin\/env \(.*\)\/bin\/wazuh-control start$/\1/p"

        if [ "X$pidir_service_name" = "Xwazuh-manager" ] || [ "X$pidir_service_name" = "Xwazuh-local" ]; then #manager, hibrid or local
            type="manager"
        else
            type="agent"
        fi

        # Get the unit file and extract the Wazuh home path
        PREINSTALLEDDIR=$(systemctl cat wazuh-${type}.service 2>/dev/null | sed -n "${SED_EXTRACT_PREINSTALLEDDIR}")
        if [ -n "${PREINSTALLEDDIR}" ] && [ -d "${PREINSTALLEDDIR}" ]; then
            return 0;
        fi

        # If fail, find the service file
        # RHEL 8 / Amazon / openSUSE Tumbleweed the services should be installed in /usr/lib/systemd/system/
        if [ -f /usr/lib/systemd/system/wazuh-${type}.service ]; then
            SERVICE_UNIT_PATH=/usr/lib/systemd/system/wazuh-${type}.service
        fi
        # Others
        if [ -f /etc/systemd/system/wazuh-${type}.service ]; then
            SERVICE_UNIT_PATH=/etc/systemd/system/wazuh-${type}.service
        fi

        if [ -f "$SERVICE_UNIT_PATH" ]; then
            PREINSTALLEDDIR=$(sed -n "${SED_EXTRACT_PREINSTALLEDDIR}" "${SERVICE_UNIT_PATH}")
            if [ -d "$PREINSTALLEDDIR" ]; then
                return 0;
            else
                return 1;
            fi
        else
            return 1;
        fi
    fi
    # Checking for Redhat system.
    if [ -r "/etc/redhat-release" ]; then
        if [ -d /etc/rc.d/init.d ]; then
            if [ -f /etc/rc.d/init.d/${pidir_service_name} ]; then
                PREINSTALLEDDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/rc.d/init.d/${pidir_service_name}`
                if [ -d "$PREINSTALLEDDIR" ]; then
                    return 0;
                else
                    return 1;
                fi
            else
                return 1;
            fi
        fi
    fi
    # Checking for Gentoo
    if [ -r "/etc/gentoo-release" ]; then
        if [ -f /etc/init.d/${pidir_service_name} ]; then
            PREINSTALLEDDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/init.d/${pidir_service_name}`
            if [ -d "$PREINSTALLEDDIR" ]; then
                return 0;
            else
                return 1;
            fi
        else
            return 1;
        fi
    fi
    # Checking for Suse
    if [ -r "/etc/SuSE-release" ]; then
        if [ -f /etc/init.d/${pidir_service_name} ]; then
            PREINSTALLEDDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/init.d/${pidir_service_name}`
            if [ -d "$PREINSTALLEDDIR" ]; then
                return 0;
            else
                return 1;
            fi
        else
            return 1;
        fi
    fi
    # Checking for Slackware
    if [ -r "/etc/slackware-version" ]; then
        if [ -f /etc/rc.d/rc.${pidir_service_name} ]; then
            PREINSTALLEDDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/rc.d/rc.${pidir_service_name}`
            if [ -d "$PREINSTALLEDDIR" ]; then
                return 0;
            else
                return 1;
            fi
        else
            return 1;
        fi
    fi
    # Checking for Darwin
    if [ "X${NUNAME}" = "XDarwin" ]; then
        if [ -f /Library/StartupItems/WAZUH/WAZUH ]; then
            PREINSTALLEDDIR=`sed -n 's/^ *//; s/^\s*\(.*\)\/bin\/wazuh-control start$/\1/p' /Library/StartupItems/WAZUH/WAZUH`
            if [ -d "$PREINSTALLEDDIR" ]; then
                return 0;
            else
                return 1;
            fi
        else
            return 1;
        fi
    fi
    # Checking for SunOS
    if [ "X${UN}" = "XSunOS" ]; then
        if [ -f /etc/init.d/${pidir_service_name} ]; then
            PREINSTALLEDDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/init.d/${pidir_service_name}`
            if [ -d "$PREINSTALLEDDIR" ]; then
                return 0;
            else
                return 1;
            fi
        else
            return 1;
        fi
    fi
    # Checking for HP-UX
    if [ "X${UN}" = "XHP-UX" ]; then
        if [ -f /sbin/init.d/${pidir_service_name} ]; then
            PREINSTALLEDDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /sbin/init.d/${pidir_service_name}`
            if [ -d "$PREINSTALLEDDIR" ]; then
                return 0;
            else
                return 1;
            fi
        else
            return 1;
        fi
    fi
    # Checking for AIX
    if [ "X${UN}" = "XAIX" ]; then
        if [ -f /etc/rc.d/init.d/${pidir_service_name} ]; then
            PREINSTALLEDDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/rc.d/init.d/${pidir_service_name}`
            if [ -d "$PREINSTALLEDDIR" ]; then
                return 0;
            else
                return 1;
            fi
        else
            return 1;
        fi
    fi
    # Checking for BSD
    if [ "X${UN}" = "XOpenBSD" -o "X${UN}" = "XNetBSD" -o "X${UN}" = "XFreeBSD" -o "X${UN}" = "XDragonFly" ]; then
        # Checking for the presence of wazuh-control on rc.local
        grep wazuh-control /etc/rc.local > /dev/null 2>&1
        if [ $? = 0 ]; then
            PREINSTALLEDDIR=`sed -n 's/^\(.*\)\/bin\/wazuh-control start$/\1/p' /etc/rc.local`
            if [ -d "$PREINSTALLEDDIR" ]; then
                return 0;
            else
                return 1;
            fi
        else
            return 1;
        fi
    elif [ "X${NUNAME}" = "XLinux" ]; then
        # Checking for Linux
        if [ -e "/etc/rc.d/rc.local" ]; then
            grep wazuh-control /etc/rc.d/rc.local > /dev/null 2>&1
            if [ $? = 0 ]; then
                PREINSTALLEDDIR=`sed -n 's/^\(.*\)\/bin\/wazuh-control start$/\1/p' /etc/rc.d/rc.local`
                if [ -d "$PREINSTALLEDDIR" ]; then
                    return 0;
                else
                    return 1;
                fi
            else
                return 1;
            fi
        # Checking for Linux (SysV)
        elif [ -d "/etc/rc.d/init.d" ]; then
            if [ -f /etc/rc.d/init.d/${pidir_service_name} ]; then
                PREINSTALLEDDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/rc.d/init.d/${pidir_service_name}`
                if [ -d "$PREINSTALLEDDIR" ]; then
                    return 0;
                else
                    return 1;
                fi
            else
                return 1;
            fi
        # Checking for Debian (Ubuntu or derivative)
        elif [ -d "/etc/init.d" -a -f "/usr/sbin/update-rc.d" ]; then
            if [ -f /etc/init.d/${pidir_service_name} ]; then
                PREINSTALLEDDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/init.d/${pidir_service_name}`
                if [ -d "$PREINSTALLEDDIR" ]; then
                    return 0;
                else
                    return 1;
                fi
            else
                return 1;
            fi
        fi
    fi

    return 1;
}

##########
# Checks if Wazuh is installed in the specified path by searching for the control binary.
#
# isWazuhInstalled()
##########
isWazuhInstalled()
{
    if [ -f "${1}/bin/wazuh-control" ]; then
        return 0;
    elif [ -f "${1}/bin/ossec-control" ]; then
        return 0;
    else
        return 1;
    fi
}

##########
# Checks if Wazuh is installed by trying with each installation type.
# If it finds an installation, it sets the PREINSTALLEDDIR variable.
# After that it checks if Wazuh is truly installed there, if it is installed it returns TRUE.
# If it isn't installed continue searching in other installation types and replacing PREINSTALLEDDIR variable.
# It returns FALSE if Wazuh isn't installed in any of this.
#
# getPreinstalledDir()
##########
getPreinstalledDir()
{
    # Checking ossec-init.conf for old wazuh versions
    if [ -f "${OSSEC_INIT}" ]; then
        . ${OSSEC_INIT}
        if [ -d "$DIRECTORY" ]; then
            PREINSTALLEDDIR="$DIRECTORY"
            if isWazuhInstalled $PREINSTALLEDDIR; then
                return 0;
            fi
        fi
    fi

    # Getting preinstalled dir for Wazuh manager and hibrid installations
    pidir_service_name="wazuh-manager"
    if getPreinstalledDirByType && isWazuhInstalled $PREINSTALLEDDIR; then
        return 0;
    fi

    # Getting preinstalled dir for Wazuh agent installations
    pidir_service_name="wazuh-agent"
    if getPreinstalledDirByType && isWazuhInstalled $PREINSTALLEDDIR; then
        return 0;
    fi

    # Getting preinstalled dir for Wazuh local installations
    pidir_service_name="wazuh-local"
    if getPreinstalledDirByType && isWazuhInstalled $PREINSTALLEDDIR; then
        return 0;
    fi

    return 1;
}

getPreinstalledType()
{
    # Checking ossec-init.conf for old wazuh versions
    if [ -f "${OSSEC_INIT}" ]; then
        . ${OSSEC_INIT}
    else
        if [ "X$PREINSTALLEDDIR" = "X" ]; then
            getPreinstalledDir
        fi

        TYPE=`$PREINSTALLEDDIR/bin/wazuh-control info -t`
    fi

    echo $TYPE
    return 0;
}

getPreinstalledVersion()
{
    # Checking ossec-init.conf for old wazuh versions
    if [ -f "${OSSEC_INIT}" ]; then
        . ${OSSEC_INIT}
    else
        if [ "X$PREINSTALLEDDIR" = "X" ]; then
            getPreinstalledDir
        fi

        VERSION=`$PREINSTALLEDDIR/bin/wazuh-control info -v`
    fi

    echo $VERSION
}

getPreinstalledName()
{
    NAME=""
    # Checking ossec-init.conf for old wazuh versions. New versions
    # do not provide this information at all.
    if [ -f "${OSSEC_INIT}" ]; then
        . ${OSSEC_INIT}
    else
        NAME="Wazuh"
    fi

    echo $NAME
}

UpdateStartOSSEC()
{
    if [ "X$TYPE" = "X" ]; then
        getPreinstalledType
    fi

    if [ "X$TYPE" != "Xagent" ]; then
        TYPE="manager"
    fi

    if [ `stat /proc/1/exe 2> /dev/null | grep "systemd" | wc -l` -ne 0 ]; then
        systemctl start wazuh-$TYPE
    elif [ `stat /proc/1/exe 2> /dev/null | grep "init.d" | wc -l` -ne 0 ]; then
        service wazuh-$TYPE start
    else
        # Considering that this function is only used after finishing the installation
        # the INSTALLDIR variable is always set. It could have either the default value,
        # or a value equals to the PREINSTALLEDDIR, or a value specified by the user.
        # The last two possibilities are set in the setInstallDir function.
        $INSTALLDIR/bin/wazuh-control start
    fi
}

UpdateStopOSSEC()
{
    MAJOR_VERSION=`echo ${VERSION} | cut -f1 -d'.' | cut -f2 -d'v'`

    if [ "X$TYPE" = "X" ]; then
        getPreinstalledType
    fi

    if [ "X$TYPE" != "Xagent" ]; then
        TYPE="manager"
        if [ $MAJOR_VERSION -ge 4 ]; then
            EMBEDDED_API_INSTALLED=1
        fi
    fi

    if [ `stat /proc/1/exe 2> /dev/null | grep "systemd" | wc -l` -ne 0 ]; then
        systemctl stop wazuh-$TYPE
    elif [ `stat /proc/1/exe 2> /dev/null | grep "init.d" | wc -l` -ne 0 ]; then
        service wazuh-$TYPE stop
    fi

    # Make sure Wazuh is stopped
    if [ "X$PREINSTALLEDDIR" = "X" ]; then
        getPreinstalledDir
    fi

    if [ -f "$PREINSTALLEDDIR/bin/ossec-control" ]; then
        $PREINSTALLEDDIR/bin/ossec-control stop > /dev/null 2>&1
    else
        $PREINSTALLEDDIR/bin/wazuh-control stop > /dev/null 2>&1
    fi

    sleep 2

   # We also need to remove all syscheck queue file (format changed)
    if [ "X$VERSION" = "X0.9-3" ]; then
        rm -f $PREINSTALLEDDIR/queue/syscheck/* > /dev/null 2>&1
        rm -f $PREINSTALLEDDIR/queue/agent-info/* > /dev/null 2>&1
    fi
    rm -rf $PREINSTALLEDDIR/framework/* > /dev/null 2>&1
    rm $PREINSTALLEDDIR/wodles/aws/aws > /dev/null 2>&1 # this script has been renamed
    rm $PREINSTALLEDDIR/wodles/aws/aws.py > /dev/null 2>&1 # this script has been renamed

    # Deleting plain-text agent information if exists (it was migrated to Wazuh DB in v4.1)
    if [ -d "$PREINSTALLEDDIR/queue/agent-info" ]; then
        rm -rf $PREINSTALLEDDIR/queue/agent-info > /dev/null 2>&1
    fi

    # Deleting plain-text rootcheck information if exists (it was migrated to Wazuh DB in v4.1)
    if [ -d "$PREINSTALLEDDIR/queue/rootcheck" ]; then
        rm -rf $PREINSTALLEDDIR/queue/rootcheck > /dev/null 2>&1
    fi

    # Deleting groups backup folder if exists
    if [ -d "$PREINSTALLEDDIR/backup/groups" ]; then
        rm -rf $PREINSTALLEDDIR/backup/groups > /dev/null 2>&1
    fi
}

UpdateOldVersions()
{

    # If it is Wazuh 2.0 or newer, exit
    if [ "X$USER_OLD_NAME" = "XWazuh" ]; then
        return
    fi

    if [ "X$PREINSTALLEDDIR" != "X" ]; then
        getPreinstalledDir
    fi

    OSSEC_CONF_FILE="$PREINSTALLEDDIR/etc/ossec.conf"
    OSSEC_CONF_FILE_ORIG="$PREINSTALLEDDIR/etc/ossec.conf.orig"

    # ossec.conf -> ossec.conf.orig
    cp -pr $OSSEC_CONF_FILE $OSSEC_CONF_FILE_ORIG

    # Delete old service
    if [ -f /etc/init.d/ossec ]; then
        rm /etc/init.d/ossec
    fi

    if [ ! "$INSTYPE" = "agent" ]; then
        # New ossec.conf by default
        ./gen_ossec.sh conf "manager" $DIST_NAME $DIST_VER > $OSSEC_CONF_FILE
        ./add_localfiles.sh $PREINSTALLEDDIR >> $OSSEC_CONF_FILE
    else
        # New ossec.conf by default
        ./gen_ossec.sh conf "agent" $DIST_NAME $DIST_VER > $OSSEC_CONF_FILE
        # Replace IP
        ./src/init/replace_manager_ip.sh $OSSEC_CONF_FILE_ORIG $OSSEC_CONF_FILE
        ./add_localfiles.sh $PREINSTALLEDDIR >> $OSSEC_CONF_FILE
    fi
}
