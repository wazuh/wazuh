#!/bin/bash
# DaemonSet entrypoint for the #36101 spike agent.
#
# Expects:
#   NODE_NAME    - injected via fieldRef (spec.nodeName)
#   MANAGER_IP   - injected via the DaemonSet env (set by deploy script)
#   /hoststate   - hostPath volume persisting enrollment + checkpoints across
#                  pod recreations (client.keys, k8s-logs/ state)
#   /var/ossec/etc/ossec.conf.template - from the ConfigMap volume
set -u

OSSEC=/var/ossec
STATE=/hoststate

echo "[entrypoint] node=$NODE_NAME manager=$MANAGER_IP"

# --- config from template -------------------------------------------------
sed -e "s/__MANAGER_IP__/$MANAGER_IP/g" -e "s/__NODE_NAME__/$NODE_NAME/g" \
    /config/ossec.conf.template > "$OSSEC/etc/ossec.conf"
chown root:wazuh "$OSSEC/etc/ossec.conf" && chmod 640 "$OSSEC/etc/ossec.conf"

# --- persistent checkpoint dir (PoC writes queue/k8s-logs/state.json) -----
mkdir -p "$STATE/k8s-logs"
rm -rf "$OSSEC/queue/k8s-logs"
ln -s "$STATE/k8s-logs" "$OSSEC/queue/k8s-logs"

# --- persistent logcollector status (file_status.json variant) ------------
mkdir -p "$STATE/logcollector"
rm -rf "$OSSEC/queue/logcollector"
ln -s "$STATE/logcollector" "$OSSEC/queue/logcollector"

# --- enrollment ------------------------------------------------------------
# 5.0 has no agent-auth binary: agentd auto-enrolls using the <enrollment>
# block (agent_name=k8s-$NODE_NAME). We persist client.keys across pod
# recreations so the agent keeps one identity per node.
if [ -s "$STATE/client.keys" ]; then
    echo "[entrypoint] restoring persisted client.keys"
    cp "$STATE/client.keys" "$OSSEC/etc/client.keys"
    chown root:wazuh "$OSSEC/etc/client.keys" && chmod 640 "$OSSEC/etc/client.keys"
fi
persist_keys_when_ready() {
    for _ in $(seq 1 60); do
        if [ -s "$OSSEC/etc/client.keys" ] && [ ! -s "$STATE/client.keys" ]; then
            cp "$OSSEC/etc/client.keys" "$STATE/client.keys"
            echo "[entrypoint] persisted client.keys to hoststate"
            return
        fi
        [ -s "$STATE/client.keys" ] && return
        sleep 2
    done
}
persist_keys_when_ready &

# --- start ------------------------------------------------------------------
# Trap TERM so `kubectl delete pod` produces a *graceful* agent stop
# (atexit checkpoint handlers run), matching a host systemd stop.
term_handler() {
    echo "[entrypoint] SIGTERM: stopping agent gracefully"
    "$OSSEC/bin/wazuh-control" stop
    exit 0
}
trap term_handler TERM INT

"$OSSEC/bin/wazuh-control" start || true
sleep 2
"$OSSEC/bin/wazuh-control" status || true

touch "$OSSEC/logs/ossec.log"
tail -F "$OSSEC/logs/ossec.log" &
wait $!
