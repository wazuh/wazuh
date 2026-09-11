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
         <key>ExitTimeOut</key>
         <integer>60</integer>
     </dict>
 </plist>' > $SERVICE

chown root:wheel $SERVICE
chmod u=rw-,go=r-- $SERVICE

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

# Arm the SIGTERM handler before bring-up so a bootout landing during the stop/start
# below still runs wazuh-control stop (deferred until the current command returns)
# instead of dying under the default disposition and leaving orphaned daemons. The
# trap persists for the poll loop below.
trap capture_sigterm SIGTERM

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
