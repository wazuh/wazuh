# Cluster Configuration Reference

Complete configuration reference for the Wazuh manager cluster.

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<cluster>`

**Daemon:** `wazuh-manager-clusterd` (manager only)

**Internal Options:** `wazuh_clusterd.debug`

For module overview and architecture, see [Cluster Module](README.md).

> **Important: how `<cluster>` is validated**
> The `<cluster>` section is part of the manager configuration schema
> (`etc/wazuh-manager.schema.json`) and is **mandatory**: a configuration without
> it is rejected (`(1244): Invalid configuration at '/': missing mandatory option
> (does not satisfy 'required')`). Every consumer — the C daemons, the engine,
> `wazuh-manager-clusterd` and the framework/API — receives the same **effective**
> section (schema-validated, defaults applied) from the `manager_config`
> loader. An invalid or incomplete block is rejected at startup with the JSON
> pointer of the offending option (`(1244): Invalid configuration at
> '/cluster/key': ...`), and `bin/wazuh-manager-conf validate` reports the same
> verdict.

---

## Configuration Options

### name

Specifies the name of the cluster this node belongs to.

- **Default value:** `wazuh`
- **Allowed values:** Any non-empty string
- **Note:** All nodes in the same cluster must use the same name: the master refuses a worker whose
  cluster name differs (error `3030`, `Worker does not belong to the same cluster`). The name is also
  an input of the `settings_hash` the manager reports to agents.

### node_name

Specifies the name of the current node of the cluster.

- **Default value:** `node01`
- **Allowed values:** Any non-empty string; a **worker** name must also consist only of letters,
  digits, `_` and `-`, or the master refuses it (error `3060`, `Invalid node name format`)
- **Note:** Each node must have a unique name. The master refuses a worker whose name is already
  connected (error `3028`, `Worker node ID already exists`) or equals its own (error `3029`,
  `Connected worker with same name as the master`).

### node_type

Specifies the role of the node.

- **Default value:** `master`
- **Allowed values:** `master`, `worker`
- **Note:** A cluster has exactly one master. The Server API (`wazuh-manager-apid`) is started only
  on the master.

### key

Defines the key used to encrypt the communication between the nodes. This key must be 32 characters long.

- **Default value:** None (required). The installer writes a random 32-character hexadecimal key
  into the generated configuration.
- **Allowed values:** Letters and digits (`^[A-Za-z0-9]{32}$`)
- **Note:** This key must be the same for all cluster nodes. A worker with a different key cannot
  decrypt the master's messages (error `3025`, `Could not decrypt message`). Because every
  installation generates its own random key, copy the master's `<key>` into each worker's
  configuration.

> **Security Warning**
> `<key>` is **required**: the schema rejects a `<cluster>` block without an
> explicit key (`(1244): Invalid configuration at '/cluster': missing
> mandatory option (does not satisfy 'required')`), so the manager does not
> start with one. There is no
> hardcoded fallback key anymore. The installer always generates a random key;
> when writing the block by hand, generate your own 32-character random value.

**Key generation:**
```bash
openssl rand -hex 16
```

### port

Specifies the port to use for cluster communications.

- **Default value:** `1516`
- **Allowed values:** `1025` to `65534`
- **Note:** The range is enforced by the configuration schema on every load,
  so a value outside it fails validation (`(1244): Invalid configuration at
  '/cluster/port'`) before any daemon starts. The port must also differ from the
  other manager listener ports (`remote.https.port`, `auth.port` while authd
  runs, and `remote.legacy.port` when the legacy listener is enabled). The master
  listens on it; workers connect to it.

### bind_addr

Specifies the address the **master** listens on for worker connections. Workers do not listen,
so they ignore it.

- **Default value:** `127.0.0.1`
- **Allowed values:** A non-empty string (the schema does not check the address format; an address
  the master cannot bind stops `wazuh-manager-clusterd` with `Could not start master`)
- **Note:** With the default, the master accepts only local connections. Set it to an address the
  workers can reach (or `0.0.0.0`) on the master of a multi-node cluster.

### nodes

The address of the master node, in a `<node>` element. Workers connect to it; the master reports
it as its own address in cluster listings.

- **Default value:** `127.0.0.1`
- **Allowed values:** One or more non-empty strings (IP address or DNS name). `localhost`,
  `0.0.0.0` and `127.0.1.1` are refused by `wazuh-manager-clusterd` at start (error `3004`,
  `Invalid elements in node fields`).
- **Note:** Only one master is allowed. If more elements are found, the first one is used and a
  warning is logged.

### hidden

Has no effect; kept for schema compatibility only.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** The schema accepts and defaults the option, but no current code path
  reads it, so it has no effect on cluster listings or on any other output. The
  installer's template still writes `<hidden>no</hidden>`.

---

## Configuration Examples

The key in these examples is illustrative: use the master's own 32-character key (see [key](#key)); it
must be the same value in every node's block.

### Master Node

Standard master node configuration:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>master-node</node_name>
  <node_type>master</node_type>
  <key>9d273b53510fef702b54a92e9cffc82e</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>MASTER_NODE_IP</node>
  </nodes>
</cluster>
```

### Worker Node

Standard worker node configuration:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>worker-node-01</node_name>
  <node_type>worker</node_type>
  <key>9d273b53510fef702b54a92e9cffc82e</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>MASTER_NODE_IP</node>
  </nodes>
</cluster>
```

### Custom Port Configuration

Use a custom port for cluster communications:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>master-node</node_name>
  <node_type>master</node_type>
  <key>9d273b53510fef702b54a92e9cffc82e</key>
  <port>5516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>MASTER_NODE_IP</node>
  </nodes>
</cluster>
```

---

## Internal Options

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`

The cluster daemon supports the following internal option:

```ini
# Cluster debug level (0-2, default: 0)
wazuh_clusterd.debug=0
```

When it is non-zero it takes precedence over the daemon's `-d` flag.

---

## See Also

- [Cluster Module](README.md) - Module overview, synchronized files, `cluster_control`
- [Cluster Load Balancing](lb.md) - Load balancing configuration
