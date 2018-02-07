#!/bin/bash
. /etc/ossec-init.conf 2> /dev/null || exit 1
(sleep 5 && chmod +x $DIRECTORY/var/upgrade/src/init/*.sh && $DIRECTORY/var/upgrade/src/init/pkg_installer.sh) >/dev/null 2>&1 &
