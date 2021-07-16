#!/usr/bin/env bash

mkdir -p /var/ossec/stats/totals/2019/Aug/
cp -rf /tmp/configuration_files/wazuh-totals-27.log /var/ossec/stats/totals/2019/Aug/wazuh-totals-27.log
chown -R wazuh:wazuh /var/ossec/stats/totals/2019/Aug/wazuh-totals-27.log
