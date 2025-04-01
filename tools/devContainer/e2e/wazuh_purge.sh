#!/bin/bash

# dpkg -c ./wazuh-server_5.0.0-0_amd64_XXX.deb | awk '{print $6}' | awk -F'/' '{print "/"$2"/"$3"/"$4"/"$5}' | sort -u | uniq
apt purge wazuh-server -y

folder_and_file=(
/bin/wazuh-apid
/bin/wazuh-comms-apid
/bin/wazuh-engine
/bin/wazuh-server
/etc/init.d/wazuh-server
/etc/wazuh-server
/etc/wazuh-server/
/run/wazuh-server/
/tmp/wazuh-server/
/usr/share/doc/wazuh-server/
/usr/share/wazuh-server/
/var/lib/wazuh-server/
/var/log/wazuh-server/
/var/wazuh-server
/var/lib/wazuh-engine
)

echo "Deleting files and folders"
for i in "${folder_and_file[@]}"
do
    echo "Deleting $i"
    rm -rf "${i}"
done

# delete wazuh-server user and group
echo "Deleting wazuh-server user and group"
userdel wazuh-server || true
groupdel wazuh-server || true
