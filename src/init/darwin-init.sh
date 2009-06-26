#!/bin/sh
# Darwin init script.
# by Lorenzo Costanzia di Costigliole <mummie@tin.it>

mkdir -p /Library/StartupItems/OSSEC
cat <<EOF >/Library/StartupItems/OSSEC/StartupParameters.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://
www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Description</key>
       <string>OSSEC Host-based Intrusion Detection System</string>
       <key>Messages</key>
       <dict>
               <key>start</key>
               <string>Starting OSSEC</string>
               <key>stop</key>
               <string>Stopping OSSEC</string>
       </dict>
       <key>Provides</key>
       <array>
               <string>OSSEC</string>
       </array>
       <key>Requires</key>
       <array>
               <string>IPFilter</string>
       </array>
</dict>
</plist>
EOF

cat <<EOF >/Library/StartupItems/OSSEC/OSSEC
#!/bin/sh

. /etc/rc.common
. /etc/ossec-init.conf
if [ "X\${DIRECTORY}" = "X" ]; then
    DIRECTORY="/var/ossec"
fi


StartService ()
{
        \${DIRECTORY}/bin/ossec-control start
}

StopService ()
{
        \${DIRECTORY}/bin/ossec-control stop
}

RestartService ()
{
        \${DIRECTORY}/bin/ossec-control restart
}

RunService "\$1"
EOF
chmod 755 /Library/StartupItems/OSSEC
chmod 644 /Library/StartupItems/OSSEC/StartupParameters.plist
chmod 755 /Library/StartupItems/OSSEC/OSSEC
