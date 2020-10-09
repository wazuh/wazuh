#!/usr/bin/env bash

wget https://packages.wazuh.com/wpk/linux/x86_64/wazuh_agent_v3.12.2_linux_x86_64.wpk
mv ./wazuh_agent_v3.12.2_linux_x86_64.wpk /var/ossec/test_custom_upgrade_3.12.2.wpk
