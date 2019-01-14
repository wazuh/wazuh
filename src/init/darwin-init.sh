#!/bin/sh

# Darwin init script.
# by Lorenzo Costanzia di Costigliole <mummie@tin.it>
# Modified by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2015-2019, Wazuh Inc.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

cat <<EOF > /Library/LaunchDaemons/com.wazuh.agent.plist
<?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
 <plist version="1.0">
 <dict>
     <key>Label</key>
     <string>com.wazuh.agent</string>
     <key>ProgramArguments</key>
     <array>
         <string>/Library/StartupItems/WAZUH/launcher.sh</string>
     </array>
     <key>RunAtLoad</key>
     <true/>
 </dict>
 </plist>
EOF

chown root:wheel /Library/LaunchDaemons/com.wazuh.agent.plist
chmod u=rw-,go=r-- /Library/LaunchDaemons/com.wazuh.agent.plist

mkdir -p /Library/StartupItems/WAZUH
chown root:wheel /Library/StartupItems/WAZUH

echo '
#!/bin/sh
. /etc/rc.common
. /etc/ossec-init.conf
if [ "X${DIRECTORY}" = "X" ]; then
    DIRECTORY="/Library/Ossec"
fi

StartService ()
{
        ${DIRECTORY}/bin/ossec-control start
}
StopService ()
{
        ${DIRECTORY}/bin/ossec-control stop
}
RestartService ()
{
        ${DIRECTORY}/bin/ossec-control restart
}
RunService "$1"
' > /Library/StartupItems/WAZUH/WAZUH

chown root:wheel /Library/StartupItems/WAZUH/WAZUH
chmod u=rwx,go=r-x /Library/StartupItems/WAZUH/WAZUH

echo '
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://
www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Description</key>
       <string>WAZUH Security agent</string>
       <key>Messages</key>
       <dict>
               <key>start</key>
               <string>Starting Wazuh agent</string>
               <key>stop</key>
               <string>Stopping Wazuh agent</string>
       </dict>
       <key>Provides</key>
       <array>
               <string>WAZUH</string>
       </array>
       <key>Requires</key>
       <array>
               <string>IPFilter</string>
       </array>
</dict>
</plist>
' > /Library/StartupItems/WAZUH/StartupParameters.plist

chown root:wheel /Library/StartupItems/WAZUH/StartupParameters.plist
chmod u=rw-,go=r-- /Library/StartupItems/WAZUH/StartupParameters.plist

echo '#!/bin/sh

. /etc/ossec-init.conf

if [ "X${DIRECTORY}" = "X" ]; then
    DIRECTORY="/Library/Ossec"
fi

capture_sigterm() {
    ${DIRECTORY}/bin/ossec-control stop
    exit $?
}

if ! ${DIRECTORY}/bin/ossec-control start; then
    ${DIRECTORY}/bin/ossec-control stop
fi

while : ; do
    trap capture_sigterm SIGTERM
    sleep 3
done
' > /Library/StartupItems/WAZUH/launcher.sh

chown root:wheel /Library/StartupItems/WAZUH/launcher.sh
chmod u=rxw-,g=rx-,o=r-- /Library/StartupItems/WAZUH/launcher.sh
