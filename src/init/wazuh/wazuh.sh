#!/bin/sh
# Install functions for the OSSEC Wazuh
# Wazuh.com (https://github.com/wazuh)

install_ruleset_updater()
{
    mkdir -p $INSTALLDIR/update/ruleset > /dev/null 2>&1
    cp -pr ./extensions/update/ruleset $INSTALLDIR/update > /dev/null 2>&1
    chown -R root:ossec $INSTALLDIR/update/ruleset > /dev/null 2>&1
    chmod 550 $INSTALLDIR/update > /dev/null 2>&1
    chmod -R 640 $INSTALLDIR/update/ruleset > /dev/null 2>&1
    chmod +x $INSTALLDIR/update/ruleset/ossec_ruleset.py > /dev/null 2>&1
    return 0;
}
patch_version(){
        rm -rf $DIRECTORY/etc/shared/ssh > /dev/null 2>&1
}
WazuhSetup(){
    DB_FILE=$INSTALLDIR/var/db/database.sqlite

    install_ruleset_updater
    patch_version

    env python ./src/init/wazuh/database.py -c -v -p $DB_FILE

    if [ "$?" = "0" ]; then
        chmod ug+w $DB_FILE
        chown root:ossec $DB_FILE
    fi
}

WazuhUpgrade()
{
    if [ -n "$USER_OLD_VERSION" ]; then
        env python ./src/init/wazuh/upgrade.py -d $INSTALLDIR $USER_OLD_VERSION
    else
        env python ./src/init/wazuh/upgrade.py -d $INSTALLDIR "v1.0"
    fi
}
