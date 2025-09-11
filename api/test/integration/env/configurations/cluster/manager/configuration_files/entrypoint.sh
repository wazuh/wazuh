#!/usr/bin/env bash

mkdir -p /var/ossec/stats/totals/2019/Aug/
cp -rf /tmp_volume/configuration_files/ossec-totals-27.log /var/ossec/stats/totals/2019/Aug/ossec-totals-27.log
chown -R wazuh:wazuh /var/ossec/stats/totals/2019/Aug/ossec-totals-27.log
