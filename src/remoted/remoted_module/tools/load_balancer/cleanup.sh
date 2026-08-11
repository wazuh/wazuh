#!/bin/bash
# Undoes everything the lab touched outside this directory.
#
# Stops the NGINX container, stops and removes the second manager node, restores the node-1
# files from ./backup, and empties the test client.keys.
#
# It does NOT stop node 1's daemons (wazuh-db, analysisd, remoted) -- you may well want to keep
# them running, so that is left to you. The final message shows how.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BACKUP="$HERE/backup"
NODE1=/var/wazuh-manager
NODE2=/var/wazuh-manager-2

echo "==> stopping the lab's NGINX"
docker rm -f remoted-lb >/dev/null 2>&1 && echo "    container removed" || echo "    not running"

echo "==> stopping manager node 2"
pkill -f "$NODE2/bin/[w]azuh-manager-remoted" 2>/dev/null && echo "    stopped" || echo "    not running"
sleep 2

echo "==> removing the node 2 tree ($NODE2)"
if [[ -d "$NODE2" ]]; then
    rm -rf "$NODE2" && echo "    removed"
else
    echo "    did not exist"
fi

echo "==> restoring node 1 files from backup/"
if [[ -d "$BACKUP" ]]; then
    for name in https-manager.cert https-manager.key https-manager-ca.pem wazuh-manager.conf; do
        if [[ -f "$BACKUP/$name" ]]; then
            cp -a "$BACKUP/$name" "$NODE1/etc/$name" && echo "    restored etc/$name"
        fi
    done
else
    echo "    no backup/ directory -- nothing to restore."
    echo "    (Back up before starting: mkdir -p backup && cp -a \\"
    echo "       $NODE1/etc/{https-manager.cert,https-manager.key,wazuh-manager.conf} backup/)"
fi

echo "==> removing the CA the lab added"
if [[ -f "$BACKUP/https-manager-ca.pem" ]]; then
    echo "    kept: etc/https-manager-ca.pem existed before the lab (restored above)"
else
    rm -f "$NODE1/etc/https-manager-ca.pem" && echo "    etc/https-manager-ca.pem removed"
fi

# The one restore combination that leaves remoted unable to start: a restored config that
# references a CA file which no longer exists (load_verify_file -> startup failure). Happens
# when the backup predates this script backing up the CA. Warn with the fix instead of letting
# the operator discover it from a dead process.
if grep -q "<ca>etc/https-manager-ca.pem</ca>" "$NODE1/etc/wazuh-manager.conf" 2>/dev/null \
        && [[ ! -f "$NODE1/etc/https-manager-ca.pem" ]]; then
    echo "    !! the restored config references etc/https-manager-ca.pem, which does not exist:"
    echo "    !! remoted will FAIL to start (load_verify_file). Remove the <ca> line or set"
    echo "    !! <verification_mode>none</verification_mode> in $NODE1/etc/wazuh-manager.conf"
fi

echo "==> emptying the test client.keys"
: > "$NODE1/etc/client.keys"
chown root:wazuh-manager "$NODE1/etc/client.keys" 2>/dev/null
chmod 660 "$NODE1/etc/client.keys" 2>/dev/null
echo "    client.keys is empty again"

echo
echo "==> done. Node 1 is still running with the restored configuration; restart remoted so it"
echo "    picks it up:"
echo "      pkill -f '$NODE1/bin/[w]azuh-manager-remoted' && $NODE1/bin/wazuh-manager-remoted"
