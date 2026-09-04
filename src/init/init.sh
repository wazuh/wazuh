#!/bin/sh

# Init functions for Wazuh
# Copyright (C) 2015, Wazuh Inc.
# Author: Daniel B. Cid <daniel.cid@gmail.com>

UN=${NUNAME};
service="wazuh";
file_permissions="wazuh-manager";

##########
# ReadServiceInstallDir() $1=path of an already installed service definition
#
# Prints the Wazuh home directory that the given service definition points to,
# or nothing when the file does not exist or no directory can be extracted.
#
# It understands the shapes the templates in src/init/templates produce --
# systemd units ("ExecStart=/usr/bin/env <home>/bin/<...>-control start") and
# init scripts ("WAZUH_HOME=<home>") -- plus the rc.local line and the macOS
# LaunchDaemon written by darwin-init.sh.
##########
ReadServiceInstallDir()
{
    if [ ! -f "${1}" ]; then
        return 1;
    fi

    # systemd unit
    _rsid_dir=$(sed -n 's|^ExecStart=/usr/bin/env \(.*\)/bin/[^[:space:]]*control start$|\1|p' "${1}" 2>/dev/null | head -1)

    # init script
    if [ "X${_rsid_dir}" = "X" ]; then
        _rsid_dir=$(sed -n 's/^WAZUH_HOME=\(.*\)$/\1/p' "${1}" 2>/dev/null | head -1)
    fi

    # rc.local
    if [ "X${_rsid_dir}" = "X" ]; then
        _rsid_dir=$(sed -n 's|^[[:space:]]*\(/.*\)/bin/[^[:space:]]*control start$|\1|p' "${1}" 2>/dev/null | head -1)
    fi

    # macOS LaunchDaemon
    if [ "X${_rsid_dir}" = "X" ]; then
        _rsid_dir=$(sed -n 's|^[[:space:]]*<string>\(/.*\)/Wazuh-launcher</string>[[:space:]]*$|\1|p' "${1}" 2>/dev/null | head -1)
    fi

    echo "${_rsid_dir}"
}

##########
# AllowServiceRegistration() $@=service definitions this install writes or overrides
#
# Guard for the boot integration. Without it, runInit() writes the host's service
# definition unconditionally, so an install into a non-default USER_DIR (a
# throwaway sandbox tree, or a package build root) silently repoints
# "systemctl start wazuh-manager" / "service wazuh-manager start" at that
# directory while the real installation still looks fine.
#
# Two preloaded variables drive it:
#   USER_REGISTER_SERVICE="n" -> never touch the boot integration.
#   USER_TAKEOVER_SERVICE="y" -> allowed to repoint an existing definition.
#
# Returns 0 when the service definitions may be written, 1 when they must be
# left untouched (runInit() then returns 1, which makes install.sh print the
# manual start command and skip the systemctl/service based auto-start).
##########
AllowServiceRegistration()
{
    if [ "X$(normalizeYesNoOrDefault "${USER_REGISTER_SERVICE}" "yes")" = "Xno" ]; then
        echo ""
        echo " - Service registration skipped (USER_REGISTER_SERVICE=\"${USER_REGISTER_SERVICE}\")."
        return 1;
    fi

    if [ "X$(normalizeYesNoOrDefault "${USER_TAKEOVER_SERVICE}" "no")" = "Xyes" ]; then
        return 0;
    fi

    for _asr_file in "$@"; do
        _asr_dir=$(ReadServiceInstallDir "${_asr_file}")

        if [ "X${_asr_dir}" = "X" ] || [ "X${_asr_dir}" = "X${INSTALLDIR}" ]; then
            continue
        fi

        echo ""
        echo " - WARNING: '${_asr_file}' already registers a Wazuh installation at:"
        echo "     ${_asr_dir}"
        echo "   This install targets '${INSTALLDIR}', so the service definition was left"
        echo "   untouched and keeps controlling '${_asr_dir}'."
        echo "   Set USER_TAKEOVER_SERVICE=\"${yes}\" to repoint the service to '${INSTALLDIR}',"
        echo "   or USER_REGISTER_SERVICE=\"${no}\" to skip the boot integration silently."
        return 1;
    done

    return 0;
}

runInit()
{
    echo ""
    echo ""
    control_script="wazuh-control"

    if [ -n "$1" ]; then
        if [ "X$1" = "Xmanager" ]; then
            service="$service-manager"
            file_permissions="wazuh-manager"
            control_script="wazuh-manager-control"
        else
            service="$service-$1"
            file_permissions="wazuh"
        fi
    fi

    update_only=$2

    # Checking for Systemd
    if hash ps 2>&1 > /dev/null && hash grep 2>&1 > /dev/null && [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        if [ "X$1" = "Xmanager" ] || [ "X$1" = "Xlocal" ]; then
            type=manager
        else
            type=agent
        fi
        # RHEL 8 services must to be installed in /usr/lib/systemd/system/
        if [ "${DIST_NAME}" = "rhel" -a "${DIST_VER}" -ge "7" ] || [ "${DIST_NAME}" = "centos" -a "${DIST_VER}" -ge "7" ]; then
            SERVICE_UNIT_PATH=/usr/lib/systemd/system/wazuh-$type.service
            RHEL_SYSTEMD_LAYOUT="yes"
        else
            SERVICE_UNIT_PATH=/etc/systemd/system/wazuh-$type.service
            RHEL_SYSTEMD_LAYOUT="no"
        fi

        # Every location systemd would pick the unit up from: a unit under
        # /etc/systemd/system overrides one shipped by a package under
        # /usr/lib (or /lib), so writing either of them can take over the
        # service of an installation living somewhere else.
        if ! AllowServiceRegistration \
            /etc/systemd/system/wazuh-$type.service \
            /usr/lib/systemd/system/wazuh-$type.service \
            /lib/systemd/system/wazuh-$type.service; then
            return 1;
        fi

        if [ "X${RHEL_SYSTEMD_LAYOUT}" = "Xyes" ]; then
            rm -f /etc/systemd/system/wazuh-$type.service
        fi
        GenerateService wazuh-$type.service > ${SERVICE_UNIT_PATH}
        chown root:$file_permissions ${SERVICE_UNIT_PATH}
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
            if ! AllowServiceRegistration /etc/rc.d/init.d/${service}; then
                return 1;
            fi
            echo " - ${systemis} Redhat Linux."
            echo " - ${modifiedinit}"
            GenerateService wazuh-rh.init > /etc/rc.d/init.d/${service}
            chmod 755 /etc/rc.d/init.d/${service}
            chown root:$file_permissions /etc/rc.d/init.d/${service}

            if [ "X${update_only}" = "X" ]
            then
                /sbin/chkconfig --add ${service} > /dev/null 2>&1
            fi

            return 0;
        fi
    fi
    # Checking for Gentoo
    if [ -r "/etc/gentoo-release" ]; then
        if ! AllowServiceRegistration /etc/init.d/${service}; then
            return 1;
        fi
        echo " - ${systemis} Gentoo Linux."
        echo " - ${modifiedinit}"
        GenerateService wazuh-gentoo.init > /etc/init.d/${service}
        chmod 755 /etc/init.d/${service}
        chown root:$file_permissions /etc/init.d/${service}

        if [ "X${update_only}" = "X" ]
        then
            rc-update add ${service} default
        fi

        return 0;
    fi

    # Suse
    if [ -r "/etc/SuSE-release" ]; then
        if ! AllowServiceRegistration /etc/init.d/${service}; then
            return 1;
        fi
        echo " - ${systemis} Suse Linux."
        echo " - ${modifiedinit}"
        GenerateService wazuh-suse.init > /etc/init.d/${service}
        chmod 755 /etc/init.d/${service}
        chown root:$file_permissions /etc/init.d/${service}

        if [ "X${update_only}" = "X" ]
        then
            /sbin/chkconfig --add ${service} > /dev/null 2>&1
        fi

        return 0;
    fi

    # Checking for slackware (by Jack S. Lai)
    if [ -r "/etc/slackware-version" ]; then
        if ! AllowServiceRegistration /etc/rc.d/rc.${service} /etc/rc.d/rc.local; then
            return 1;
        fi
        echo " - ${systemis} Slackware Linux."
        echo " - ${modifiedinit}"
        GenerateService wazuh.init > /etc/rc.d/rc.${service}
        chmod 755 /etc/rc.d/rc.${service}
        chown root:$file_permissions /etc/rc.d/rc.${service}

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

        if ! AllowServiceRegistration /Library/LaunchDaemons/com.wazuh.agent.plist; then
            return 1;
        fi
        echo " - ${systemis} Darwin."
        echo " - ${modifiedinit}"
        sh ./src/init/darwin-init.sh ${INSTALLDIR}
        return 0;
    fi

    if [ "X${UN}" = "XOpenBSD" -o "X${UN}" = "XNetBSD" -o "X${UN}" = "XFreeBSD" -o "X${UN}" = "XDragonFly" ]; then
        if ! AllowServiceRegistration /etc/rc.local; then
            return 1;
        fi
        # Checking for the presence of the control script on rc.local
        grep ${control_script} /etc/rc.local > /dev/null 2>&1
        if [ $? != 0 ]; then
            echo "echo \"${starting}\"" >> /etc/rc.local
            echo "${INSTALLDIR}/bin/${control_script} start" >> /etc/rc.local
        fi
        echo " - ${systemis} ${NUNAME}."
        echo " - ${modifiedinit}"
        return 0;
    elif [ "X${NUNAME}" = "XLinux" ]; then
        if [ -e "/etc/rc.d/rc.local" ]; then
            if ! AllowServiceRegistration /etc/rc.d/rc.local; then
                return 1;
            fi
            echo " - ${systemis} Linux."
            echo " - ${modifiedinit}"

            grep ${control_script} /etc/rc.d/rc.local > /dev/null 2>&1
            if [ $? != 0 ]; then
                echo "echo \"${starting}\"" >> /etc/rc.d/rc.local
                echo "${INSTALLDIR}/bin/${control_script} start" >> /etc/rc.d/rc.local
            fi
            return 0;
        elif [ -d "/etc/rc.d/init.d" ]; then
            if ! AllowServiceRegistration /etc/rc.d/init.d/${service}; then
                return 1;
            fi
            echo " - ${systemis} Linux (SysV)."
            echo " - ${modifiedinit}"
            GenerateService wazuh.init > /etc/rc.d/init.d/${service}
            chmod 755 /etc/rc.d/init.d/${service}
            chown root:$file_permissions /etc/rc.d/init.d/${service}
            return 0;
        # Taken from Stephen Bunn ossec howto.
        elif [ -d "/etc/init.d" -a -f "/usr/sbin/update-rc.d" ]; then
            if ! AllowServiceRegistration /etc/init.d/${service}; then
                return 1;
            fi
            echo " - ${systemis} Debian (Ubuntu or derivative)."
            echo " - ${modifiedinit}"
            GenerateService wazuh-debian.init > /etc/init.d/${service}
            chmod +x /etc/init.d/${service}
            chmod go-w /etc/init.d/${service}
            chown root:$file_permissions /etc/init.d/${service}

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
