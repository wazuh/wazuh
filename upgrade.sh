#!/bin/bash

(sleep 5 && chmod +x /var/ossec/var/incoming/wazuh_pkg/src/init/*.sh && /var/ossec/var/incoming/wazuh_pkg/src/init/pkg_installer.sh) >/dev/null 2>&1 &
