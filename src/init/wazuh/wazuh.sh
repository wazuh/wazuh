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

    # Remove existing SQLite databases

    rm -f $DIRECTORY/var/db/global.db*
    rm -f $DIRECTORY/var/db/.profile.db*
    rm -f $DIRECTORY/var/db/.template.db*
    rm -f $DIRECTORY/var/db/agents/*

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

    # Remove OpenSCAP policies if the module is disabled
    if stat $DIRECTORY/wodles/oscap/content/* > /dev/null ; then
        if grep -n '<wodle name="open-scap">' $DIRECTORY/etc/ossec.conf > /dev/null ; then
            is_disabled="no"
        else
            is_disabled="yes"
        fi

        end_config_limit="99999999"
        for start_config in $(grep -n '<wodle name="open-scap">'  $DIRECTORY/etc/ossec.conf | cut -d':' -f 1); do
            end_config="$(sed -n "${start_config},${end_config_limit}p"  $DIRECTORY/etc/ossec.conf | sed -n '/open-scap/,$p' | grep -n '</wodle>' | head -n 1 | cut -d':' -f 1)"
            end_config="$((start_config + end_config))"

            if [ -n "${start_config}" ] && [ -n "${end_config}" ]; then
                open_scap_conf="$(sed -n "${start_config},${end_config}p"  $DIRECTORY/etc/ossec.conf)"

                for line in $(echo ${open_scap_conf} | grep -n '<disabled>' | cut -d':' -f 1); do
                    # Check if OpenSCAP is enabled
                    if echo ${open_scap_conf} | sed -n ${line}p | grep "disabled>no" > /dev/null ; then
                        is_disabled="no"

                    # Check if OpenSCAP is disabled
                    elif echo ${open_scap_conf} | sed -n ${line}p | grep "disabled>yes" > /dev/null; then
                        is_disabled="yes"
                    fi
                done
            fi
        done

        if [ "${is_disabled}" = "yes" ]; then
            rm -f $DIRECTORY/wodles/oscap/content/*
        fi
    fi
}
