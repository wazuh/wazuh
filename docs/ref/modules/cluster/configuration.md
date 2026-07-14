# Cluster Configuration Reference

Complete configuration reference for the Wazuh manager cluster.

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<cluster>`

**Module:** Manager-only

**Internal Options:** `wazuh_clusterd.*`

For module overview and architecture, see [Cluster Module](index.html).

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

**Key generation:**
```bash
openssl rand -hex 16
```

### port

Specifies the port to use for cluster communications.

- **Default value:** `1516`
- **Allowed values:** Any port number higher than 1024 and lower than 65535

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
