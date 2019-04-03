#!/usr/bin/env bash

. /etc/ossec-init.conf
sed -i "s:<key></key>:<key>9d273b53510fef702b54a92e9cffc82e</key>:g" "${DIRECTORY}/etc/ossec.conf"
sed -i "s:<node>NODE_IP</node>:<node>$1</node>:g" "${DIRECTORY}/etc/ossec.conf"
sed -i -e "/<cluster>/,/<\/cluster>/ s|<disabled>[a-z]\+</disabled>|<disabled>no</disabled>|g" "${DIRECTORY}/etc/ossec.conf"
sed -i "s:<node_name>node01</node_name>:<node_name>$2</node_name>:g" "${DIRECTORY}/etc/ossec.conf"

if [ "X$3" != "Xmaster" ]; then
    sed -i "s:<node_type>master</node_type>:<node_type>worker</node_type>:g" "${DIRECTORY}/etc/ossec.conf"
fi

"${DIRECTORY}/bin/ossec-control" restart

node "${DIRECTORY}/api/app.js" &
tail -f "${DIRECTORY}/logs/cluster.log"
