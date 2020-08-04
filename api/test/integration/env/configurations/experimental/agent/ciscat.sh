#!/usr/bin/env bash

apt-get update && apt-get install openjdk-8-jdk -y
cp -rf /configuration_files/test.keys /var/ossec/etc/test.keys
cp -rf /configuration_files/ciscat /var/ossec/wodles/
chown -R ossec:ossec /var/ossec/wodles/ciscat
cd /var/ossec/wodles/ciscat && if [ -e CIS-CAT.sh ]; then chmod +x CIS-CAT.sh ; fi
