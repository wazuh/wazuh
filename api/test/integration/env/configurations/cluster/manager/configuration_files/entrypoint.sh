#!/usr/bin/env bash

sed -i -e "/<\/ossec_config>/i   <reports>\n  <title>Auth_Report</title>\n  <group>authentication_failed,</group>\n  <srcip>192.168.1.10</srcip>\n  <showlogs>yes</showlogs>\n  </reports>" /var/ossec/etc/ossec.conf
mkdir -p /var/ossec/stats/totals/2019/Aug/
cp -rf /tmp_volume/configuration_files/ossec-totals-27.log /var/ossec/stats/totals/2019/Aug/ossec-totals-27.log
chown -R wazuh:wazuh /var/ossec/stats/totals/2019/Aug/ossec-totals-27.log
