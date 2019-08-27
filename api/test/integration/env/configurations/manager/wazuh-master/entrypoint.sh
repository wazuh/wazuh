#!/usr/bin/env bash

# Set right permissions for test_config data
chown root:ossec /var/ossec/etc/ossec.conf
chown root:ossec /var/ossec/etc/client.keys
chown -R ossec:ossec /var/ossec/queue/agent-groups
chown -R ossecr:ossec /var/ossec/var/multigroups
chown -R ossec:ossec /var/ossec/etc/shared
chown root:ossec /var/ossec/etc/shared/ar.conf
chown -R ossecr:ossec /var/ossec/queue/agent-info
chown -R ossecr:ossec /var/ossec/stats/totals/2019/Aug/ossec-totals-27.log

# (Already in copied ossec.conf)
#sed -i "s:<key></key>:<key>9d273b53510fef702b54a92e9cffc82e</key>:g" /var/ossec/etc/ossec.conf
#sed -i "s:<node>NODE_IP</node>:<node>$1</node>:g" /var/ossec/etc/ossec.conf
#sed -i -e "/<cluster>/,/<\/cluster>/ s|<disabled>[a-z]\+</disabled>|<disabled>no</disabled>|g" /var/ossec/etc/ossec.conf
#sed -i "s:<node_name>node01</node_name>:<node_name>$2</node_name>:g" /var/ossec/etc/ossec.conf

# Add this to configure with nginx load balancer (Already in copied ossec.conf)
#sed -i "s:<use_source_ip>yes</use_source_ip>:<use_source_ip>no</use_source_ip>:g" /var/ossec/etc/ossec.conf
#sed -i "s:<protocol>udp</protocol>:<protocol>tcp</protocol>:g" /var/ossec/etc/ossec.conf

#if [ "X$3" != "Xmaster" ]; then
#    sed -i "s:<node_type>master</node_type>:<node_type>worker</node_type>:g" /var/ossec/etc/ossec.conf
#fi

#filebeat -e &

sleep 1

/var/ossec/bin/ossec-control start

/usr/bin/supervisord
