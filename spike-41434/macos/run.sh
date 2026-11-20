#!/bin/bash
# Runs every macOS candidate against the same driver scenarios. Results go to out/.
set -x
O=$PWD/out; mkdir -p "$O"
{ sw_vers; uname -m; csrutil status; } > "$O/env.txt" 2>&1

clang -O2 -o ports ports.c && clang -O2 -o nstat nstat.c -framework CoreFoundation && clang -O2 -o kq kq.c
clang -O2 -o inv inv.c -framework CoreServices -framework SystemConfiguration
clang -O2 -o esc esc.c -lEndpointSecurity -lbsm

# Endpoint Security, own client: unsigned (no entitlement), then ad-hoc signed with the entitlement (works only with SIP off).
{ echo "## unsigned"; sudo ./esc 1; echo "rc=$?"; } > "$O/es_unsigned.txt" 2>&1
cp esc esc_ent && codesign -f -s - --entitlements es.plist esc_ent
for sdk in /Applications/Xcode*.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX[0-9]*.sdk; do
  echo "## $sdk"; grep -n -B1 'RESERVED_[3-6]' "$sdk/usr/include/EndpointSecurity/ESTypes.h"
done > "$O/sdk_headers.txt" 2>&1

# Collectors: ES client, libproc at 1 s and 100 ms, NetworkStatistics.
sudo ./esc_ent > "$O/es.jsonl" 2> "$O/es.err" &
sudo ./ports 1000 > "$O/ports_1000.jsonl" &
sudo ./ports 100 > "$O/ports_100.jsonl" &
sudo ./nstat > "$O/nstat.jsonl" 2> "$O/nstat.err" &
# Inventory fixtures: a tiny pkg, an app bundle plist, the per-user LaunchAgents folder.
mkdir -p pkgroot "$HOME/Library/LaunchAgents" && echo poc > pkgroot/wzpoc.txt
pkgbuild --quiet --root pkgroot --identifier com.wazuh.wzpoc --version 1.0 --install-location /usr/local/share/wzpoc wzpoc.pkg
printf '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleName</key><string>WzPoc</string></dict></plist>' > Info.plist
sudo ./inv /Applications /private/var/db/receipts /opt/homebrew/Cellar /usr/local/Cellar /opt/local/var/macports/registry \
  /Library/LaunchDaemons /Library/LaunchAgents "$HOME/Library/LaunchAgents" "$HOME/Library/Application Support" \
  /private/var/db/dslocal/nodes/Default "$HOME/Applications" > "$O/inv.jsonl" 2> "$O/inv.err" &
sleep 10
python3 driver.py > "$O/truth.jsonl"
HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ENV_HINTS=1 python3 inv_driver.py > "$O/inv_truth.jsonl"
curl -s -o /dev/null https://example.com  # one outbound connect for event 154
sleep 3
ps -o pid,user,time,rss,command -p "$(pgrep -d, -x 'esc_ent|ports|nstat|inv')" > "$O/cpu.txt"
sudo pkill -TERM -x ports; sudo pkill -TERM -x nstat; sudo pkill -TERM -x esc_ent; sudo pkill -TERM -x inv
sleep 2
sudo log show --last 3m --style compact --predicate 'subsystem CONTAINS "endpointsecurity" OR sender == "EndpointSecurity"' | grep -iv 'disconnected' | tail -15 > "$O/es_log.txt" 2>&1

# NetworkStatistics without root: does it see a root-owned listener?
{ ./nstat > "$O/nstat_user.jsonl" & sleep 1
  sudo -n python3 -c 'import socket,time;s=socket.socket();s.bind(("127.0.0.1",48124));s.listen();time.sleep(1)'
  sleep 1; kill %1; grep -c '|48124"' "$O/nstat_user.jsonl"; } > "$O/nstat_user.txt" 2>&1

# kqueue: exit status for a child, a non-child, and a root non-child.
{ ./kq; (sleep 1; exit 9) & ./kq $!
  sudo -n sh -c 'echo $$ > /tmp/kqpid; sleep 1; exit 8' & sleep 0.3; ./kq "$(cat /tmp/kqpid)"; } > "$O/kqueue.txt" 2>&1

# OpenBSM: is auditd still shipped, and does it record exec/exit/bind once enabled (host change)?
{ ls /usr/sbin/auditd /System/Library/LaunchDaemons/com.apple.auditd.plist /etc/security/
  [ -f /etc/security/audit_control ] || sudo cp /etc/security/audit_control.example /etc/security/audit_control
  sudo sed -i '' -e 's/^flags:.*/flags:ex,pc,nt/' -e 's/^naflags:.*/naflags:ex,pc,nt/' /etc/security/audit_control
  sudo grep flags /etc/security/audit_control
  sudo launchctl enable system/com.apple.auditd
  sudo launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist
  sudo audit -i; sleep 1; sudo audit -s; sleep 2; pgrep -l auditd; sudo launchctl print system/com.apple.auditd | grep -E 'state|disabled|last exit' 
  /bin/sh -c 'exit 5'; python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",48123));s.listen()'
  sleep 2; sudo audit -n; sleep 1
  sudo ls -la /var/audit; sudo log show --last 2m --style compact --predicate 'process == "auditd"' | tail -5
  sudo sh -c 'for f in /var/audit/2*; do praudit -l "$f"; done' > "$O/audit.txt"
  grep -E 'socket-inet,2,48123|exit 5' "$O/audit.txt"
  pid=$(grep 'exit 5' "$O/audit.txt" | grep -o 'subject,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,[0-9]*' | head -1 | cut -d, -f7)
  grep "exit(2).*subject,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,$pid," "$O/audit.txt"
} > "$O/openbsm.txt" 2>&1

python3 analyze.py "$O" | tee "$O/summary.md"
