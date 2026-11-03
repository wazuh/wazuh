# Staged overrides

Empty on purpose. This directory is mounted read-only at `/lab-overrides` on **wazuh-worker2**,
and the manager entrypoint sources every `*.sh` it finds here, on every boot, after it has
written the configuration and before it starts the daemons.

Empty means the lab comes up healthy. To inject a fault, copy a scenario in and restart that
node:

```bash
cp ../scenarios/break-indexer-ca.sh .
docker restart wazuh-worker2
```

and to undo it, remove the file and restart again. Scenarios run with the entrypoint's own
variables in scope -- `$CONF` is the manager configuration, `$DIR` the install root.

Only `wazuh-worker2` mounts this: injecting a fault into one node of three is the whole point,
and it is the node `cert_drill.sh` also targets, so a degraded node is always the same node.

Nothing here is committed except this file.
