#!/bin/sh

# Copyright (C) 2015-2020, Wazuh Inc.
# Shell script update functions for Wazuh
# Author: Daniel B. Cid <daniel.cid@gmail.com>

FALSE="false"
TRUE="true"

##########
# Checks whether this is an update by verifying if Wazuh is installed in the default
# directory, the one specified by the user, or the services files exists.
#
# isUpdate()
##########
isUpdate()
{
    # Checking ossec-init.conf for old wazuh versions
    if [ -f "${OSSEC_INIT}" ]; then
        . ${OSSEC_INIT}
        if [ "X$DIRECTORY" = "X" ]; then
            echo "# ($FUNCNAME) ERROR: The variable DIRECTORY wasn't set in the old Wazuh installation." 1>&2
            echo "${FALSE}"
            return 1;
        fi
        if [ -d "$DIRECTORY" ]; then
            OLDINSTALLDIR="$DIRECTORY"
            echo "${TRUE}"
            return 0;
        fi
    fi

    # Checking if Wazuh is installed in the default directory
    if [ -d "$DEFAULT_DIR" ]; then
        OLDINSTALLDIR="$DEFAULT_DIR"
        echo "${TRUE}"
        return 0;
    fi

    # Checking if Wazuh is installed in the directory set by the user
    if [ -d "$INSTALLDIR" ]; then
        OLDINSTALLDIR="$INSTALLDIR"
        echo "${TRUE}"
        return 0;
    fi

    # Checking if the Wazuh services files exists
    if [ "X$INSTYPE" = "Xserver" ]; then
        service="wazuh-manager"
    else
        service="wazuh-$INSTYPE"
    fi
    # Checking for Systemd
    if hash ps 2>&1 > /dev/null && hash grep 2>&1 > /dev/null && [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        if [ "X$INSTYPE" = "Xserver" ] || [ "X$INSTYPE" = "Xlocal" ]; then
            type=manager
        else
            type=agent
        fi
        # RHEL 8 services should be installed in /usr/lib/systemd/system/
        if [ "${DIST_NAME}" = "rhel" -a "${DIST_VER}" = "8" ] || [ "${DIST_NAME}" = "centos" -a "${DIST_VER}" = "8" ]; then
            SERVICE_UNIT_PATH=/usr/lib/systemd/system/wazuh-$type.service
        else
            SERVICE_UNIT_PATH=/etc/systemd/system/wazuh-$type.service
        fi

        if [ -f "$SERVICE_UNIT_PATH" ]; then
            OLDINSTALLDIR=`sed -n 's/^ExecStart=\/usr\/bin\/env \(.*\)\/bin\/wazuh-control start$/\1/p' $SERVICE_UNIT_PATH`
            if [ -d "$OLDINSTALLDIR" ]; then
                echo "${TRUE}"
                return 0;
            else
                echo "${FALSE}"
                return 1;
            fi
        else
            echo "${FALSE}"
            return 1;
        fi
    fi
    # Checking for Redhat system.
    if [ -r "/etc/redhat-release" ]; then
        if [ -d /etc/rc.d/init.d ]; then
            if [ -f /etc/rc.d/init.d/${service} ]; then
                OLDINSTALLDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/rc.d/init.d/${service}`
                if [ -d "$OLDINSTALLDIR" ]; then
                    echo "${TRUE}"
                    return 0;
                else
                    echo "${FALSE}"
                    return 1;
                fi
            else
                echo "${FALSE}"
                return 1;
            fi
        fi
    fi
    # Checking for Gentoo
    if [ -r "/etc/gentoo-release" ]; then
        if [ -f /etc/init.d/${service} ]; then
            OLDINSTALLDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/init.d/${service}`
            if [ -d "$OLDINSTALLDIR" ]; then
                echo "${TRUE}"
                return 0;
            else
                echo "${FALSE}"
                return 1;
            fi
        else
            echo "${FALSE}"
            return 1;
        fi
    fi
    # Checking for Suse
    if [ -r "/etc/SuSE-release" ]; then
        if [ -f /etc/init.d/${service} ]; then
            OLDINSTALLDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/init.d/${service}`
            if [ -d "$OLDINSTALLDIR" ]; then
                echo "${TRUE}"
                return 0;
            else
                echo "${FALSE}"
                return 1;
            fi
        else
            echo "${FALSE}"
            return 1;
        fi
    fi
    # Checking for Slackware
    if [ -r "/etc/slackware-version" ]; then
        if [ -f /etc/rc.d/rc.${service} ]; then
            OLDINSTALLDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/rc.d/rc.${service}`
            if [ -d "$OLDINSTALLDIR" ]; then
                echo "${TRUE}"
                return 0;
            else
                echo "${FALSE}"
                return 1;
            fi
        else
            echo "${FALSE}"
            return 1;
        fi
    fi
    # Checking for Darwin
    if [ "X${NUNAME}" = "XDarwin" ]; then
        if [ -f /Library/StartupItems/WAZUH/WAZUH ]; then
            OLDINSTALLDIR=`sed -n 's/^\s*\(.*\)\/bin\/wazuh-control start$/\1/p' /Library/StartupItems/WAZUH/WAZUH`
            if [ -d "$OLDINSTALLDIR" ]; then
                echo "${TRUE}"
                return 0;
            else
                echo "${FALSE}"
                return 1;
            fi
        else
            echo "${FALSE}"
            return 1;
        fi
    fi
    # Checking for SunOS
    if [ "X${UN}" = "XSunOS" ]; then
        if [ -f /etc/init.d/${service} ]; then
            OLDINSTALLDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/init.d/${service}`
            if [ -d "$OLDINSTALLDIR" ]; then
                echo "${TRUE}"
                return 0;
            else
                echo "${FALSE}"
                return 1;
            fi
        else
            echo "${FALSE}"
            return 1;
        fi
    fi
    # Checking for HP-UX
    if [ "X${UN}" = "XHP-UX" ]; then
        if [ -f /sbin/init.d/${service} ]; then
            OLDINSTALLDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /sbin/init.d/${service}`
            if [ -d "$OLDINSTALLDIR" ]; then
                echo "${TRUE}"
                return 0;
            else
                echo "${FALSE}"
                return 1;
            fi
        else
            echo "${FALSE}"
            return 1;
        fi
    fi
    # Checking for AIX
    if [ "X${UN}" = "XAIX" ]; then
        if [ -f /etc/rc.d/init.d/${service} ]; then
            OLDINSTALLDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/rc.d/init.d/${service}`
            if [ -d "$OLDINSTALLDIR" ]; then
                echo "${TRUE}"
                return 0;
            else
                echo "${FALSE}"
                return 1;
            fi
        else
            echo "${FALSE}"
            return 1;
        fi
    fi
    # Checking for BSD
    if [ "X${UN}" = "XOpenBSD" -o "X${UN}" = "XNetBSD" -o "X${UN}" = "XFreeBSD" -o "X${UN}" = "XDragonFly" ]; then
        # Checking for the presence of wazuh-control on rc.local
        grep wazuh-control /etc/rc.local > /dev/null 2>&1
        if [ $? = 0 ]; then
            OLDINSTALLDIR=`sed -n 's/^\(.*\)\/bin\/wazuh-control start$/\1/p' /etc/rc.local`
            if [ -d "$OLDINSTALLDIR" ]; then
                echo "${TRUE}"
                return 0;
            else
                echo "${FALSE}"
                return 1;
            fi
        else
            echo "${FALSE}"
            return 1;
        fi
    elif [ "X${NUNAME}" = "XLinux" ]; then
        # Checking for Linux
        if [ -e "/etc/rc.d/rc.local" ]; then
            grep wazuh-control /etc/rc.d/rc.local > /dev/null 2>&1
            if [ $? = 0 ]; then
                OLDINSTALLDIR=`sed -n 's/^\(.*\)\/bin\/wazuh-control start$/\1/p' /etc/rc.d/rc.local`
                if [ -d "$OLDINSTALLDIR" ]; then
                    echo "${TRUE}"
                    return 0;
                else
                    echo "${FALSE}"
                    return 1;
                fi
            else
                echo "${FALSE}"
                return 1;
            fi
        # Checking for Linux (SysV)
        elif [ -d "/etc/rc.d/init.d" ]; then
            if [ -f /etc/rc.d/init.d/${service} ]; then
                OLDINSTALLDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/rc.d/init.d/${service}`
                if [ -d "$OLDINSTALLDIR" ]; then
                    echo "${TRUE}"
                    return 0;
                else
                    echo "${FALSE}"
                    return 1;
                fi
            else
                echo "${FALSE}"
                return 1;
            fi
        # Checking for Debian (Ubuntu or derivative)
        elif [ -d "/etc/init.d" -a -f "/usr/sbin/update-rc.d" ]; then
            if [ -f /etc/init.d/${service} ]; then
            OLDINSTALLDIR=`sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' /etc/init.d/${service}`
                if [ -d "$OLDINSTALLDIR" ]; then
                    echo "${TRUE}"
                    return 0;
                else
                    echo "${FALSE}"
                    return 1;
                fi
            else
                echo "${FALSE}"
                return 1;
            fi
        fi
    fi

    echo "${FALSE}"
    return 1;
}

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

getPreinstalled()
{
    . ${OSSEC_INIT}

	echo $TYPE
    return 0;
}

getPreinstalledDir()
{
    . ${OSSEC_INIT}
    echo "$DIRECTORY"
    return 0;
}

getPreinstalledVersion()
{
    . ${OSSEC_INIT}
    echo $VERSION
}

getPreinstalledName()
{
    NAME=""
    . ${OSSEC_INIT}
    echo $NAME
}

UpdateStartOSSEC()
{
   . ${OSSEC_INIT}

   if [ "X$TYPE" != "Xagent" ]; then
       TYPE="manager"
   fi

   if [ `stat /proc/1/exe 2> /dev/null | grep "systemd" | wc -l` -ne 0 ]; then
       systemctl start wazuh-$TYPE
   elif [ `stat /proc/1/exe 2> /dev/null | grep "init.d" | wc -l` -ne 0 ]; then
       service wazuh-$TYPE start
   else
       $DIRECTORY/bin/wazuh-control start
   fi
}

UpdateStopOSSEC()
{
    if [ -f ${OSSEC_INIT} ]
    then
        . ${OSSEC_INIT}

        MAJOR_VERSION=`echo ${VERSION} | cut -f1 -d'.' | cut -f2 -d'v'`

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
    else
        echo "      WARN: No such file ${OSSEC_INIT}. Trying to stop Wazuh..."
        DIRECTORY=${INSTALLDIR}
    fi

    # Make sure Wazuh is stopped
    if [ -f "$DIRECTORY/bin/ossec-control" ]; then
        $DIRECTORY/bin/ossec-control stop > /dev/null 2>&1
    else
        $DIRECTORY/bin/wazuh-control stop > /dev/null 2>&1
    fi
    sleep 2

   # We also need to remove all syscheck queue file (format changed)
    if [ "X$VERSION" = "X0.9-3" ]; then
        rm -f $DIRECTORY/queue/syscheck/* > /dev/null 2>&1
        rm -f $DIRECTORY/queue/agent-info/* > /dev/null 2>&1
    fi
    rm -rf $DIRECTORY/framework/* > /dev/null 2>&1
    rm $DIRECTORY/wodles/aws/aws > /dev/null 2>&1 # this script has been renamed
    rm $DIRECTORY/wodles/aws/aws.py > /dev/null 2>&1 # this script has been renamed

    # Deleting plain-text agent information if exists (it was migrated to Wazuh DB in v4.1)
    if [ -d "$DIRECTORY/queue/agent-info" ]; then
        rm -rf $DIRECTORY/queue/agent-info > /dev/null 2>&1
    fi

    # Deleting plain-text rootcheck information if exists (it was migrated to Wazuh DB in v4.1)
    if [ -d "$DIRECTORY/queue/rootcheck" ]; then
        rm -rf $DIRECTORY/queue/rootcheck > /dev/null 2>&1
    fi
}

UpdateOldVersions()
{
    if [ "$INSTYPE" = "server" ]; then
        # Delete deprecated rules & decoders
        echo "Searching for deprecated rules and decoders..."
        DEPRECATED=`cat ./src/init/wazuh/deprecated_ruleset.txt`
        for i in $DEPRECATED; do
            DEL_FILE="$INSTALLDIR/ruleset/$i"
            if [ -f ${DEL_FILE} ]; then
                echo "Deleting '${DEL_FILE}'."
                rm -f ${DEL_FILE}
            fi
        done
    fi

    # If it is Wazuh 2.0 or newer, exit
    if [ "X$USER_OLD_NAME" = "XWazuh" ]; then
        return
    fi

    OSSEC_CONF_FILE="$DIRECTORY/etc/ossec.conf"
    OSSEC_CONF_FILE_ORIG="$DIRECTORY/etc/ossec.conf.orig"

    # ossec.conf -> ossec.conf.orig
    cp -pr $OSSEC_CONF_FILE $OSSEC_CONF_FILE_ORIG

    # Delete old service
    if [ -f /etc/init.d/ossec ]; then
        rm /etc/init.d/ossec
    fi

    if [ ! "$INSTYPE" = "agent" ]; then

        # Delete old update ruleset
        if [ -d "$DIRECTORY/update" ]; then
            rm -rf "$DIRECTORY/update"
        fi

        ETC_DECODERS="$DIRECTORY/etc/decoders"
        ETC_RULES="$DIRECTORY/etc/rules"

        # Moving local_decoder
        if [ -f "$DIRECTORY/etc/local_decoder.xml" ]; then
            if [ -s "$DIRECTORY/etc/local_decoder.xml" ]; then
                mv "$DIRECTORY/etc/local_decoder.xml" $ETC_DECODERS
            else
                # it is empty
                rm -f "$DIRECTORY/etc/local_decoder.xml"
            fi
        fi

        # Moving local_rules
        if [ -f "$DIRECTORY/rules/local_rules.xml" ]; then
            mv "$DIRECTORY/rules/local_rules.xml" $ETC_RULES
        fi

        # Creating backup directory
        BACKUP_RULESET="$DIRECTORY/etc/backup_ruleset"
        mkdir $BACKUP_RULESET > /dev/null 2>&1
        chmod 750 $BACKUP_RULESET > /dev/null 2>&1
        chown root:ossec $BACKUP_RULESET > /dev/null 2>&1

        # Backup decoders: Wazuh v1.0.1 to v1.1.1
        old_decoders="ossec_decoders wazuh_decoders"
        for old_decoder in $old_decoders
        do
            if [ -d "$DIRECTORY/etc/$old_decoder" ]; then
                mv "$DIRECTORY/etc/$old_decoder" $BACKUP_RULESET
            fi
        done

        # Backup decoders: Wazuh v1.0 and OSSEC
        if [ -f "$DIRECTORY/etc/decoder.xml" ]; then
            mv "$DIRECTORY/etc/decoder.xml" $BACKUP_RULESET
        fi

        # Backup rules: All versions
        mv "$DIRECTORY/rules" $BACKUP_RULESET

        # New ossec.conf by default
        ./gen_ossec.sh conf "manager" $DIST_NAME $DIST_VER > $OSSEC_CONF_FILE
        ./add_localfiles.sh $DIRECTORY >> $OSSEC_CONF_FILE
    else
        # New ossec.conf by default
        ./gen_ossec.sh conf "agent" $DIST_NAME $DIST_VER > $OSSEC_CONF_FILE
        # Replace IP
        ./src/init/replace_manager_ip.sh $OSSEC_CONF_FILE_ORIG $OSSEC_CONF_FILE
        ./add_localfiles.sh $DIRECTORY >> $OSSEC_CONF_FILE
    fi
}
