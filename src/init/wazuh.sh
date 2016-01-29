#!/bin/sh
# Install functions for the OSSEC Wazuh
# Wazuh.com (https://github.com/wazuh)

install_ruleset_updater()
{
    mkdir -p $INSTALLDIR/update/ruleset
    cp -pr ./extensions/update/ruleset $INSTALLDIR/update
    chown -R root:ossec $INSTALLDIR/update/ruleset
    chmod 550 $INSTALLDIR/update
    chmod -R 640 $INSTALLDIR/update/ruleset
    chmod +x $INSTALLDIR/update/ruleset/ossec_ruleset.py
    return 0;
}
