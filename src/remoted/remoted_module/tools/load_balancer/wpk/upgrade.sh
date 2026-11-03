#!/bin/sh
# Benign upgrade payload: proves the WPK reached the agent, its signature verified and the
# installer ran, WITHOUT reinstalling the agent (which would end the lab session it runs in).
echo "$(date -u +%FT%TZ) lab upgrade.sh executed on $(hostname)" >> /var/ossec/logs/lab-upgrade.log
echo "0" > /var/ossec/var/upgrade/upgrade_result 2>/dev/null || true
exit 0
