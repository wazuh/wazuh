#!/usr/bin/env bash

mkdir -p /var/wazuh-manager/stats/totals/2019/Aug/
cp -rf /tmp_volume/configuration_files/ossec-totals-27.log /var/wazuh-manager/stats/totals/2019/Aug/ossec-totals-27.log
chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/stats/totals/2019/Aug/ossec-totals-27.log