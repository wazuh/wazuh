#!/bin/bash

(sleep 5 && chmod +x /var/ossec/var/upgrade/src/init/*.sh && /var/ossec/var/upgrade/src/init/pkg_installer.sh) >/dev/null 2>&1 &
