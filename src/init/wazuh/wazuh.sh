#!/bin/sh

#Copyright (C) 2015-2020, Wazuh Inc.
# Install functions for Wazuh
# Wazuh.com (https://github.com/wazuh)

patch_version(){
        rm -rf $DIRECTORY/etc/shared/ssh > /dev/null 2>&1
}
WazuhSetup(){
    patch_version
}

InstallSELinuxPolicyPackage(){

    if command -v semodule > /dev/null && command -v getenforce > /dev/null; then
        if [ -f selinux/wazuh.pp ]; then
            if [ $(getenforce) != "Disabled" ]; then
                cp selinux/wazuh.pp /tmp && semodule -i /tmp/wazuh.pp
                rm -f /tmp/wazuh.pp
                semodule -e wazuh
            fi
        fi
    fi
}

CheckModuleIsEnabled(){
    # This function requires a properly formatted ossec.conf.
    # It doesn't work if the configuration is set in the same line

    # How to use it:
    #
    # CheckModuleIsEnabled '<wodle name="open-scap">' '</wodle>' 'disabled'
    # CheckModuleIsEnabled '<cluster>' '</cluster>' 'disabled'
    # CheckModuleIsEnabled '<sca>' '</sca>' 'enabled'

    open_label="$1"
    close_label="$2"
    enable_label="$3"

    if grep -n "${open_label}" $DIRECTORY/etc/ossec.conf > /dev/null ; then
        is_disabled="no"
    else
        is_disabled="yes"
    fi

    if [ "${enable_label}" = "disabled" ]; then
        tag="<disabled>"
        enabled_tag="${tag}no"
        disabled_tag="${tag}yes"
    else
        tag="<enabled>"
        enabled_tag="${tag}yes"
        disabled_tag="${tag}no"
    fi

    end_config_limit="99999999"
    for start_config in $(grep -n "${open_label}" $DIRECTORY/etc/ossec.conf | cut -d':' -f 1); do
        end_config="$(sed -n "${start_config},${end_config_limit}p" $DIRECTORY/etc/ossec.conf | sed -n "/${open_label}/,\$p" | grep -n "${close_label}" | head -n 1 | cut -d':' -f 1)"
        end_config="$((start_config + end_config))"

        if [ -n "${start_config}" ] && [ -n "${end_config}" ]; then
            configuration_block="$(sed -n "${start_config},${end_config}p" $DIRECTORY/etc/ossec.conf)"

            for line in $(echo ${configuration_block} | grep -n "${tag}" | cut -d':' -f 1); do
                # Check if the component is enabled
                if echo ${configuration_block} | sed -n ${line}p | grep "${enabled_tag}" > /dev/null ; then
                    is_disabled="no"

                # Check if the component is disabled
                elif echo ${configuration_block} | sed -n ${line}p | grep "${disabled_tag}" > /dev/null; then
                    is_disabled="yes"
                fi
            done
        fi
    done

    echo ${is_disabled}
}

WazuhUpgrade()
{
    # Encode Agentd passlist if not encoded

    passlist=$DIRECTORY/agentless/.passlist

    if [ -f $passlist ] && ! base64 -d $passlist > /dev/null 2>&1; then
        cp $passlist $passlist.bak
        base64 $passlist.bak > $passlist

        if [ $? = 0 ]; then
            echo "Agentless passlist encoded successfully."
            rm -f $passlist.bak
        else
            echo "ERROR: Couldn't encode Agentless passlist."
            mv $passlist.bak $passlist
        fi
    fi

    # Remove/relocate existing SQLite databases
    rm -f $DIRECTORY/var/db/.profile.db*
    rm -f $DIRECTORY/var/db/.template.db*
    rm -f $DIRECTORY/var/db/agents/*

    if [ -f "$DIRECTORY/var/db/global.db" ]; then
        cp $DIRECTORY/var/db/global.db $DIRECTORY/queue/db/
        if [ -f "$DIRECTORY/queue/db/global.db" ]; then
            chmod 640 $DIRECTORY/queue/db/global.db
            chown ossec:ossec $DIRECTORY/queue/db/global.db
            rm -f $DIRECTORY/var/db/global.db*
        else
            echo "Unable to move global.db during the upgrade"
        fi
    fi

    # Remove existing SQLite databases for Wazuh DB, only if upgrading from 3.2..3.6

    MAJOR=$(echo $USER_OLD_VERSION | cut -dv -f2 | cut -d. -f1)
    MINOR=$(echo $USER_OLD_VERSION | cut -d. -f2)

    if [ $MAJOR = 3 ] && [ $MINOR -lt 7 ]
    then
        rm -f $DIRECTORY/queue/db/*.db*
    fi
    rm -f $DIRECTORY/queue/db/.template.db

    # Remove existing SQLite databases for vulnerability-detector

    rm -f $DIRECTORY/wodles/cve.db
    rm -f $DIRECTORY/queue/vulnerabilities/cve.db

    # Remove deprecated Wazuh tools

    rm -f $DIRECTORY/bin/ossec-control
    rm -f $DIRECTORY/bin/ossec-regex
    rm -f $DIRECTORY/bin/ossec-logtest
    rm -f $DIRECTORY/bin/ossec-makelists
    rm -f $DIRECTORY/bin/util.sh
    rm -f $DIRECTORY/bin/rootcheck_control
	rm -f $DIRECTORY/bin/syscheck_control
	rm -f $DIRECTORY/bin/syscheck_update

    # Remove old Wazuh daemons

    rm -f $DIRECTORY/bin/ossec-agentd
    rm -f $DIRECTORY/bin/ossec-agentlessd
    rm -f $DIRECTORY/bin/ossec-analysisd
    rm -f $DIRECTORY/bin/ossec-authd
    rm -f $DIRECTORY/bin/ossec-csyslogd
    rm -f $DIRECTORY/bin/ossec-dbd
    rm -f $DIRECTORY/bin/ossec-execd
    rm -f $DIRECTORY/bin/ossec-integratord
    rm -f $DIRECTORY/bin/ossec-logcollector
    rm -f $DIRECTORY/bin/ossec-maild
    rm -f $DIRECTORY/bin/ossec-monitord
    rm -f $DIRECTORY/bin/ossec-remoted
    rm -f $DIRECTORY/bin/ossec-reportd
    rm -f $DIRECTORY/bin/ossec-syscheckd

    # Remove existing ruleset version file

    rm -f $DIRECTORY/ruleset/VERSION

    # Remove deprecated ossec-init.conf file and its link
    if [ -f /etc/ossec-init.conf ]; then
        rm -f $DIRECTORY/etc/ossec-init.conf
        rm -f /etc/ossec-init.conf
    fi
}
