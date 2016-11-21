#!/bin/sh
# Install functions for Wazuh
# Wazuh.com (https://github.com/wazuh)

install_ruleset_updater()
{
    mkdir -p $INSTALLDIR/update/ruleset > /dev/null 2>&1
    cp -pr ./extensions/update/ruleset $INSTALLDIR/update > /dev/null 2>&1
    chown -R root:ossec $INSTALLDIR/update/ruleset > /dev/null 2>&1
    chmod 750 $INSTALLDIR/update > /dev/null 2>&1
    chmod -R 640 $INSTALLDIR/update/ruleset > /dev/null 2>&1
    chmod +x $INSTALLDIR/update/ruleset/ossec_ruleset.py > /dev/null 2>&1
    return 0;
}
patch_version(){
        rm -rf $DIRECTORY/etc/shared/ssh > /dev/null 2>&1
}
WazuhSetup(){
    install_ruleset_updater
    patch_version
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
}
