#!/usr/bin/env bash

sed -i "s:<key></key>:<key>9d273b53510fef702b54a92e9cffc82e</key>:g" /var/ossec/etc/ossec.conf
sed -i "s:<node>NODE_IP</node>:<node>$1</node>:g" /var/ossec/etc/ossec.conf
sed -i -e "/<cluster>/,/<\/cluster>/ s|<disabled>[a-z]\+</disabled>|<disabled>no</disabled>|g" /var/ossec/etc/ossec.conf
sed -i "s:<node_name>NODE_NAME</node_name>:<node_name>$2</node_name>:g" /var/ossec/etc/ossec.conf

# Add this to configure with nginx load balancer
sed -i "s:<use_source_ip>yes</use_source_ip>:<use_source_ip>no</use_source_ip>:g" /var/ossec/etc/ossec.conf
sed -i "s:<protocol>udp</protocol>:<protocol>tcp</protocol>:g" /var/ossec/etc/ossec.conf

if [ "X$3" != "Xmaster" ]; then
    sed -i "s:<node_type>NODE_TYPE</node_type>:<node_type>worker</node_type>:g" /var/ossec/etc/ossec.conf
else

    sed -i "s:<node_type>NODE_TYPE</node_type>:<node_type>master</node_type>:g" /var/ossec/etc/ossec.conf

fi

sleep 1

/var/ossec/bin/ossec-control start

/usr/bin/supervisord
