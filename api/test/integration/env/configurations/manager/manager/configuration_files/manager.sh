#!/usr/bin/env bash

if [ "$HOSTNAME" == "wazuh-master" ]; then
  sed -i -e "/<cluster>/,/<\/cluster>/ s|<disabled>[a-z]\+</disabled>|<disabled>yes</disabled>|g" /var/ossec/etc/ossec.conf
  rm -rf /var/ossec/stats/totals/*
  mkdir -p /var/ossec/stats/totals/2019/Aug/
  cp -rf configuration_files/ossec-totals-27.log /var/ossec/stats/totals/2019/Aug/ossec-totals-27.log
  chown -R ossec:ossec /var/ossec/stats/totals/2019/Aug/ossec-totals-27.log
fi
