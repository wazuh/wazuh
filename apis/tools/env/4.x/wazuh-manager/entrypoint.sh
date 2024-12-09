#!/usr/bin/env bash

if [ "$3" == "master" ]
then
    python3 /scripts/xml_parser.py /var/ossec/etc/ossec.conf /scripts/master_ossec_conf.xml
    sed -i "s:# access:access:g" /var/ossec/api/configuration/api.yaml
    sed -i "s:#  max_request_per_minute\: 300:  max_request_per_minute\: 99999:g" /var/ossec/api/configuration/api.yaml
else
    python3 /scripts/xml_parser.py /var/ossec/etc/ossec.conf /scripts/worker_ossec_conf.xml
fi

sed -i "s:wazuh_db.debug=0:wazuh_db.debug=2:g" /var/ossec/etc/internal_options.conf
sed -i "s:authd.debug=0:authd.debug=2:g" /var/ossec/etc/internal_options.conf
sed -i "s:remoted.debug=0:remoted.debug=2:g" /var/ossec/etc/internal_options.conf

sleep 1

service wazuh-manager start

# Keep the container running
while true; do
    sleep 10
done
