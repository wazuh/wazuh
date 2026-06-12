# Cluster Configuration

This guide covers the configuration and deployment requirements for the Wazuh manager cluster.

## Overview

The Wazuh cluster allows multiple manager nodes to work together for high availability and load distribution. The cluster uses a dedicated internal protocol (DAPI) over port 1516 for node-to-node communication.

Cluster configuration is defined in `/var/wazuh-manager/etc/wazuh-manager.conf` under the `<cluster>` section.

## Configuration Options

### name

Specifies the name of the cluster this node belongs to.

- **Default value**: `wazuh`
- **Allowed values**: Any name

All nodes in the same cluster must use the same name.

### node_name

Specifies the name of the current node of the cluster.

- **Default value**: `node01`
- **Allowed values**: Any name

Each node of the cluster must have a unique name. If two nodes share the same name, one of them will be rejected.

### node_type

Specifies the role of the node.

- **Default value**: `master`
- **Allowed values**: `master`, `worker`

The current cluster implementation allows only one master node.

### key

Defines the key used to encrypt the communication between the nodes. This key must be 32 characters long.

- **Default value**: Value randomly produced during node installation.
- **Allowed values**: Letters, digits, and underscores (32 characters)

This key must be the same for all of the cluster nodes.

**Key generation example**:
```bash
openssl rand -hex 16
```

To modify the key manually for all workers, do this in master node:

```bash
grep '<key>' /var/wazuh-manager/etc/wazuh-manager.conf

# Once copied, copy it in each worker node and then restart the manager:
sudo sed -i 's|<key>.*</key>|<key>PASTE_MASTER_KEY_HERE</key>|' /var/wazuh-manager/etc/wazuh-manager.conf
sudo systemctl restart wazuh-manager
```

### port

Specifies the port to use for the cluster communications.

- **Default value**: `1516`
- **Allowed values**: Any port number higher than 1024 and lower than 65535

### bind_addr

Specifies which IP address will communicate with the cluster when the node has multiple network interfaces.

- **Default value**: `127.0.0.1`
- **Allowed values**: Any valid IP address

### nodes

Lists all master nodes in the cluster using the `<node>` tag for each one.

- **Default value**: `127.0.0.1`
- **Allowed values**: Any valid address (IP or DNS) of a cluster node

The current cluster only allows one master node. Therefore, this list must have only one element. If more elements are found, the first one will be used as master, and the rest will be ignored.

### hidden

Toggles whether or not to show information about the cluster that generated an alert. If this is set to `yes`, information about the cluster that generated the event won't be included in the alert.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

> **Note for users migrating from Wazuh 4.x:** The `<disabled>` option present in 4.x cluster configuration is no longer processed in 5.0. Cluster enable/disable is controlled at the service level — to disable the cluster, stop or disable the `wazuh-manager-clusterd` service. If `<disabled>` is present in the configuration file it is silently ignored.

## Configuration Example

### Master Node

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

Replace `MASTER_NODE_IP` with the actual IP address of the master node.

### Worker Node

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

Replace `MASTER_NODE_IP` with the actual IP address of the master node, and use a unique `node_name` for each worker.

## Applying Configuration Changes

After editing `/var/wazuh-manager/etc/wazuh-manager.conf` on each node, restart the manager service:

```bash
systemctl restart wazuh-manager
```

Verify cluster status:

```bash
/var/wazuh-manager/bin/cluster_control -l
```

Expected output shows all nodes connected:
```
NAME              TYPE    VERSION  ADDRESS
master-node       master  4.x.x    10.0.1.10
worker-node-01    worker  4.x.x    10.0.1.11
```

## Deployment Requirements

The cluster security model assumes specific deployment conditions that are **mandatory operational requirements**.

### Network Isolation

**Requirement**: Port 1516 must be restricted to a dedicated management network segment accessible only to cluster nodes.

The cluster protocol is an internal control plane, not a user-facing API. It must not be reachable from:
- Agent networks
- User networks
- The Internet
- Any untrusted network segment

**Implementation**:

Use firewall rules to restrict access. Example using iptables:

```bash
# Allow cluster traffic only from known node IPs
iptables -A INPUT -p tcp --dport 1516 -s <master-node-ip> -j ACCEPT
iptables -A INPUT -p tcp --dport 1516 -s <worker-node-1-ip> -j ACCEPT
iptables -A INPUT -p tcp --dport 1516 -s <worker-node-2-ip> -j ACCEPT
# Drop all other traffic to cluster port
iptables -A INPUT -p tcp --dport 1516 -j DROP
```

Alternative methods:
- Dedicated VLAN for cluster communication
- Security groups (cloud environments) restricting port 1516 to cluster node IPs only
- Private network / VPN for multi-datacenter clusters

### Cluster Key Management

**Requirement**: Treat the cluster key as a root credential.

The key in the `<key>` parameter is the sole authentication mechanism for cluster membership. Possession of this key grants full cluster access.

**Best practices**:

- Generate a cryptographically secure random key
- Use unique keys per environment (never reuse keys across production, staging, development)
- Restrict file permissions on `wazuh-manager.conf`:
  ```bash
  chown root:wazuh-manager /var/wazuh-manager/etc/wazuh-manager.conf
  chmod 640 /var/wazuh-manager/etc/wazuh-manager.conf
  ```
- Consider storing the key in a secrets management system
- Establish a key rotation schedule according to your security policy
- Never commit keys to version control

### Node Hardening

**Requirement**: Secure cluster nodes as critical infrastructure.

Each cluster node has full administrative authority over all other nodes. A compromised node means a compromised cluster.

**Hardening measures**:
- Keep systems patched and up-to-date
- Apply OS-level security controls (SELinux, AppArmor, firewall)
- Restrict SSH access (key-based authentication, limited users)
- Enable audit logging
- Deploy host-based intrusion detection
- Minimize installed software and running services
- Use dedicated systems for cluster nodes

### Monitoring

**Requirement**: Monitor cluster communication for anomalies.

Monitor for:
- Unexpected connections to port 1516 from unknown IPs
- Cluster authentication failures
- Node disconnections or synchronization failures
- Changes to cluster configuration files

**Monitoring commands**:

```bash
# Check cluster status
/var/wazuh-manager/bin/cluster_control -l

# View cluster logs
tail -f /var/wazuh-manager/logs/cluster.log

# Monitor active connections to cluster port
ss -tnp | grep :1516
```

## Troubleshooting

### Cluster nodes not connecting

Check network connectivity from worker to master:
```bash
telnet <master-ip> 1516
```

Verify cluster key matches across all nodes:
```bash
grep -A 10 '<cluster>' /var/wazuh-manager/etc/wazuh-manager.conf | grep '<key>'
```

Check firewall rules:
```bash
iptables -L -n -v | grep 1516
```

Review cluster logs:
```bash
tail -100 /var/wazuh-manager/logs/cluster.log
```

### Authentication failures

If logs show authentication errors, verify:
- All nodes use the exact same cluster key (32 characters: letters, digits, and underscores)
- Cluster name is identical across all nodes
- No special characters beyond letters, digits, and underscores in the key

### Network configuration issues

If nodes disconnect after network changes:
- Verify `bind_addr` matches the node's actual IP address
- Check routing tables and network segmentation rules
- Ensure firewall rules allow bidirectional traffic on port 1516
- Restart the manager service on all affected nodes

## Security Model

For detailed information on the cluster security architecture, trust boundaries, and what constitutes a vulnerability, see the [Cluster Security Model](../security/cluster-model.md).

Key security principles:
- The cluster operates within a single authority context where nodes are privileged peers
- RBAC is enforced at the API entry point (port 55000), not within cluster communication
- Network isolation of port 1516 is a deployment requirement, not optional
- See the security model documentation for CVSS considerations and threat scenarios
