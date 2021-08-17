#!/bin/bash
# Copyright (C) 2015-2021, Wazuh Inc.

# validate OS, linux or macos
if [ "$(uname)" = "Linux" ] ; then
    (sleep 5 && chmod +x ./var/upgrade/src/init/*.sh && ./var/upgrade/src/init/pkg_installer.sh && find ./var/upgrade/* -not -name upgrade_result -delete) >/dev/null 2>&1 &
else
    (sleep 5 && chmod +x ./var/upgrade/*.sh && ./var/upgrade/pkg_installer.sh && find ./var/upgrade/ -mindepth 1 -not -name upgrade_result -delete) >/dev/null 2>&1 &
fi
