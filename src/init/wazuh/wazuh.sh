#!/bin/sh
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
                if ! (semodule -l | grep wazuh > /dev/null); then
                    echo "Installing Wazuh policy for SELinux..."
                    cp selinux/wazuh.pp /tmp && semodule -i /tmp/wazuh.pp
                    rm -f /tmp/wazuh.pp
                    semodule -e wazuh
                else
                    echo "Skipping installation of Wazuh policy for SELinux: module already installed."
                fi
            else
                echo "Skipping installation of Wazuh policy: SELinux is disabled."
            fi
        else
            echo "WARN: Could not install Wazuh policy for SELinux: the module was not compiled."
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

    # Remove existing SQLite databases for Wazuh DB

    rm -f $DIRECTORY/queue/db/*.db*
    rm -f $DIRECTORY/queue/db/.template.db

    # Remove existing SQLite databases for vulnerability-detector

    rm -f $DIRECTORY/wodles/cve.db
    rm -f $DIRECTORY/queue/vulnerabilities/cve.db
}
