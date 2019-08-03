#!/bin/bash
# Copyright (C) 2015-2019, Wazuh Inc.
. /etc/ossec-init.conf 2> /dev/null || exit 1
(sleep 5 && chmod +x $DIRECTORY/var/upgrade/src/init/*.sh && $DIRECTORY/var/upgrade/src/init/pkg_installer.sh) >/dev/null 2>&1 &
