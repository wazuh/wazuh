#!/bin/sh

# Darwin init script.
# by Lorenzo Costanzia di Costigliole <mummie@tin.it>
# Modified by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2015-2020, Wazuh Inc.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

SERVICE=/Library/LaunchDaemons/com.wazuh.agent.plist
STARTUP=/Library/StartupItems/WAZUH/StartupParameters.plist
LAUNCHER_SCRIPT=/Library/StartupItems/WAZUH/launcher.sh
STARTUP_SCRIPT=/Library/StartupItems/WAZUH/WAZUH

launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist 2> /dev/null
mkdir -p /Library/StartupItems/WAZUH
chown root:wheel /Library/StartupItems/WAZUH
rm -f $STARTUP $STARTUP_SCRIPT $SERVICE
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
launchctl load $SERVICE

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
' > $STARTUP_SCRIPT

chown root:wheel $STARTUP_SCRIPT
chmod u=rwx,go=r-x $STARTUP_SCRIPT

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
' > $STARTUP

chown root:wheel $STARTUP
chmod u=rw-,go=r-- $STARTUP

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
' > $LAUNCHER_SCRIPT
