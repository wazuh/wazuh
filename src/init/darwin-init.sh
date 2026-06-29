#!/bin/sh

# Darwin init script.
# by Lorenzo Costanzia di Costigliole <mummie@tin.it>
# Modified by Wazuh, Inc. <info@wazuh.com>.
# Copyright (C) 2015, Wazuh Inc.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

INSTALLATION_PATH=${1}
SERVICE=/Library/LaunchDaemons/com.wazuh.agent.plist
STARTUP=/Library/StartupItems/WAZUH/StartupParameters.plist
LAUNCHER_SCRIPT=/Library/StartupItems/WAZUH/Wazuh-launcher
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
         <key>ExitTimeOut</key>
         <integer>60</integer>
     </dict>
 </plist>' > $SERVICE

chown root:wheel $SERVICE
chmod u=rw-,go=r-- $SERVICE

echo '
#!/bin/sh
. /etc/rc.common

StartService ()
{
        '${INSTALLATION_PATH}'/bin/wazuh-control start
}
StopService ()
{
        '${INSTALLATION_PATH}'/bin/wazuh-control stop
}
RestartService ()
{
        '${INSTALLATION_PATH}'/bin/wazuh-control restart
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

# Wazuh-launcher: anchor process of the launchd job (com.wazuh.agent).
# It starts the agent and then stays alive, polling for control requests
# dropped by wazuh-modulesd. Running reload/restart from here -- a shell
# launched by launchd -- preserves the same TCC "responsible process" lineage
# as boot, so wazuh-syscheckd keeps its own Full Disk Access entry instead of
# inheriting wazuh-modulesd as the responsible process. See
# src/wazuh_modules/src/wm_control.c (writer of the request flag).

CONTROL_REQUEST='${INSTALLATION_PATH}'/var/run/wazuh-control.request
CONTROL_REQUEST_INFLIGHT="$CONTROL_REQUEST.inflight"

capture_sigterm() {
    '${INSTALLATION_PATH}'/bin/wazuh-control stop
    exit $?
}

# Drop any request left over from a previous run: the agent is about to start
# fresh with the current configuration, so a stale request must not trigger a
# spurious reload.
rm -f "$CONTROL_REQUEST" "$CONTROL_REQUEST_INFLIGHT" "$CONTROL_REQUEST.tmp"

# Clean slate before starting. A previous bootout may have been killed by launchd
# (ExitTimeOut) before wazuh-control stop finished, leaving a daemon still alive;
# wazuh-control start would then see it as "already running" and skip it, leaving e.g.
# wazuh-modulesd down after a restart. A stop here terminates any such
# leftover (it is a fast no-op on a clean boot) so the start below always brings every
# daemon up fresh.
'${INSTALLATION_PATH}'/bin/wazuh-control stop > /dev/null 2>&1

if ! '${INSTALLATION_PATH}'/bin/wazuh-control start; then
    '${INSTALLATION_PATH}'/bin/wazuh-control stop
fi

while : ; do
    trap capture_sigterm SIGTERM
    # Atomically claim the request via rename: if mv succeeds we own it, which
    # closes the read-then-remove race against the writer.
    if mv "$CONTROL_REQUEST" "$CONTROL_REQUEST_INFLIGHT" 2>/dev/null; then
        action=`cat "$CONTROL_REQUEST_INFLIGHT" 2>/dev/null`
        rm -f "$CONTROL_REQUEST_INFLIGHT"
        case "$action" in
            reload|restart)
                '${INSTALLATION_PATH}'/bin/wazuh-control "$action"
                ;;
        esac
    fi
    sleep 3
done
' > $LAUNCHER_SCRIPT
