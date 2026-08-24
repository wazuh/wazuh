# Cluster Configuration Reference

Complete configuration reference for the Wazuh manager cluster.

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<cluster>`

**Module:** Manager-only

**Internal Options:** `wazuh_clusterd.*`

For module overview and architecture, see [Cluster Module](index.html).

> **Important: where `<cluster>` is actually parsed**
> The shared C configuration library (`src/config/src/config.c`) recognizes
> the `<cluster>` tag but does not parse or validate it — the corresponding
> branch is empty and simply swallows the tag, doing no processing at the C
> level. All parsing and validation of the `<cluster>` section happens later,
> in Python:
> - `utils.read_cluster_config` performs lenient parsing (filling in missing
>   fields with defaults, including the hardcoded fallback key described
>   below) and is used generally whenever the framework/API reads cluster
>   configuration.
> - `cluster.check_cluster_config` performs strict validation, but only runs
>   at `wazuh-clusterd` daemon startup and during `cluster_control` CLI
>   validation.
>
> In other words, the shared C configuration library provides **no safety
> net** for this section: an invalid or incomplete `<cluster>` block will
> pass through the C parser without error, and how strictly it is later
> validated depends entirely on which Python code path reads it.

---

## Configuration Options

### name

Specifies the name of the cluster this node belongs to.

- **Default value:** `wazuh`
- **Allowed values:** Any name
- **Note:** All nodes in the same cluster must use the same name

### node_name

Specifies the name of the current node of the cluster.

- **Default value:** `node01`
- **Allowed values:** Any name
- **Note:** Each node must have a unique name. If two nodes share the same name, one will be rejected.

### node_type

Specifies the role of the node.

- **Default value:** `master`
- **Allowed values:** `master`, `worker`
- **Note:** The current cluster implementation allows only one master node

### key

Defines the key used to encrypt the communication between the nodes. This key must be 32 characters long.

- **Default value:** Value randomly produced during node installation
- **Allowed values:** Letters, digits, and underscores (32 characters)
- **Note:** This key must be the same for all cluster nodes

> **Security Warning**
> The "randomly produced" default described above only applies to the
> `<cluster>` block generated automatically by the installer. If you manually
> write or edit a `<cluster>` configuration block, you **must** include an
> explicit, randomly-generated `<key>` value. Omitting `<key>` (or any other
> field) from a manually-written `<cluster>` block does **not** cause a new
> random key to be generated: `read_cluster_config` silently substitutes a
> hardcoded, shared literal value (`fd3350b86d239654e34866ab3c4988a8`) for
> any missing field, including `key`. This means every installation that
> omits `<key>` from a manual configuration ends up using the same
> well-known secret, which is a serious security risk in production
> environments.

**Key generation:**
```bash
openssl rand -hex 16
```

### port

Specifies the port to use for cluster communications.

- **Default value:** `1516`
- **Allowed values:** Any port number higher than 1024 and lower than 65535
- **Note:** This range is only enforced by `check_cluster_config`, which runs
  at `wazuh-clusterd` daemon startup and during `cluster_control` CLI
  validation. It is **not** enforced by `read_cluster_config`, the function
  used generally by the framework/API when reading cluster configuration
  elsewhere (e.g. `GET /cluster/config`); that path only performs a lenient
  `isdigit()` check with no range validation. A port outside this range can
  therefore be read back and reported by the API even though it would fail
  validation at daemon startup.

### bind_addr

Specifies which IP address will communicate with the cluster when the node has multiple network interfaces.

- **Default value:** `127.0.0.1`
- **Allowed values:** Any valid IP address

### nodes

Lists all master nodes in the cluster using the `<node>` tag for each one.

- **Default value:** `127.0.0.1`
- **Allowed values:** Any valid address (IP or DNS) of a cluster node
- **Note:** Only one master node allowed. If more elements are found, the first one will be used.

### hidden

Toggles whether or not to show information about the cluster that generated an alert.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** This option does not appear to affect any current code path — a
  repository-wide search found no location where `config_cluster['hidden']`
  is read to influence alert output. Treat it as reserved/legacy pending
  further investigation.

---

## Configuration Examples

### Master Node

Standard master node configuration:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>master-node</node_name>
  <node_type>master</node_type>
  <key>c98b62a9b6169ac5f67dfe55b73a8d2a</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>MASTER_NODE_IP</node>
  </nodes>
  <hidden>no</hidden>
</cluster>
```

### Worker Node

Standard worker node configuration:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>worker-node-01</node_name>
  <node_type>worker</node_type>
  <key>c98b62a9b6169ac5f67dfe55b73a8d2a</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>MASTER_NODE_IP</node>
  </nodes>
  <hidden>no</hidden>
</cluster>
```

### Custom Port Configuration

Use a custom port for cluster communications:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>master-node</node_name>
  <node_type>master</node_type>
  <key>c98b62a9b6169ac5f67dfe55b73a8d2a</key>
  <port>5516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>MASTER_NODE_IP</node>
  </nodes>
  <hidden>no</hidden>
</cluster>
```

### Hide Cluster Information

Configure cluster to hide node information in alerts:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>master-node</node_name>
  <node_type>master</node_type>
  <key>c98b62a9b6169ac5f67dfe55b73a8d2a</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>MASTER_NODE_IP</node>
  </nodes>
  <hidden>yes</hidden>
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

---

## See Also

- [Cluster Module](index.html) - Module overview and architecture
- [Cluster Load Balancing](lb.md) - Load balancing configuration
