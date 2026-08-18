#!/bin/bash
# Copyright (C) 2015, Wazuh Inc.

# Pure-shell cleanup of the upgrade directory (keeps upgrade_result), so it does
# not depend on `find`, which may be absent on minimal images.
clean_upgrade_dir() {
    for f in ./var/upgrade/*; do
        [ "$f" = "./var/upgrade/upgrade_result" ] && continue
        rm -rf "$f"
    done
}

# validate OS, linux or macos
if [ "X$(uname)" = "XLinux" ] ; then
    # Get Wazuh installation path
    SCRIPT=$(readlink -f "$0")
    WAZUH_HOME=$(dirname $(dirname $(dirname "$SCRIPT")))
    cd "${WAZUH_HOME}"
    (sleep 5 && chmod +x ./var/upgrade/*.sh && ./var/upgrade/pkg_installer.sh && clean_upgrade_dir) >> ./logs/upgrade.log 2>&1 &
else
    (sleep 5 && chmod +x ./var/upgrade/*.sh && ./var/upgrade/pkg_installer.sh && clean_upgrade_dir) >> ./logs/upgrade.log 2>&1 &
fi
