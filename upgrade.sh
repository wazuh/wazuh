#!/bin/bash
# Copyright (C) 2015, Wazuh Inc.

# Testing-only flag to bypass the manager reachability check (used by WPK
# smoke tests that upgrade without a real manager available).
if [ "$1" = "--skip-manager-check" ]; then
    export WAZUH_UPGRADE_TEST_SKIP_MANAGER_CHECK=1
fi

# validate OS, linux or macos
if [ "X$(uname)" = "XLinux" ] ; then
    # Get Wazuh installation path
    SCRIPT=$(readlink -f "$0")
    WAZUH_HOME=$(dirname $(dirname $(dirname "$SCRIPT")))
    cd "${WAZUH_HOME}"
    (sleep 5 && chmod +x ./var/upgrade/*.sh && ./var/upgrade/pkg_installer.sh && find ./var/upgrade/* -not -name upgrade_result -delete) >/dev/null 2>&1 &
else
    (sleep 5 && chmod +x ./var/upgrade/*.sh && ./var/upgrade/pkg_installer.sh && find ./var/upgrade/ -mindepth 1 -not -name upgrade_result -delete) >/dev/null 2>&1 &
fi
