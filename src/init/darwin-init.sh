#!/bin/sh

# Darwin init script.
# by Lorenzo Costanzia di Costigliole <mummie@tin.it>
# Modified by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2015, Wazuh Inc.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

INSTALLATION_PATH=${1}
SERVICE=/Library/LaunchDaemons/com.wazuh.agent.plist
LAUNCHER_SCRIPT=${INSTALLATION_PATH}/Wazuh-launcher

launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist 2> /dev/null

# Remove the legacy StartupItems service left by older packages. The LaunchDaemon
# below is now the only service definition; StartupItems is a pre-launchd boot
# mechanism macOS no longer invokes, and its presence alongside the LaunchDaemon
# was the duplicate "Login item" this script used to create.
rm -rf /Library/StartupItems/WAZUH

rm -f $SERVICE
echo > $LAUNCHER_SCRIPT
chown root:wheel $LAUNCHER_SCRIPT
chmod u=rxw-,g=rx-,o=r-- $LAUNCHER_SCRIPT

echo '<?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
 <plist version="1.0">
     <dict>
         <key>Label</key>
         <string>com.wazuh.agent</string>
         <key>ProgramArguments</key>
         <array>
             <string>'$LAUNCHER_SCRIPT'</string>
         </array>
         <key>RunAtLoad</key>
         <true/>
     </dict>
 </plist>' > $SERVICE

chown root:wheel $SERVICE
chmod u=rw-,go=r-- $SERVICE

echo '#!/bin/sh

capture_sigterm() {
    '${INSTALLATION_PATH}'/bin/wazuh-control stop
    exit $?
}

if ! '${INSTALLATION_PATH}'/bin/wazuh-control start; then
    '${INSTALLATION_PATH}'/bin/wazuh-control stop
fi

while : ; do
    trap capture_sigterm SIGTERM
    sleep 3
done
' > $LAUNCHER_SCRIPT
