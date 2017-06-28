#!/bin/bash

(sleep 5 && /var/ossec/var/incoming/wazuh_pkg/install.sh >> /var/ossec/var/incoming/wazuh_pkg/upgrade.log 2>&1) >/dev/null 2>&1 &
