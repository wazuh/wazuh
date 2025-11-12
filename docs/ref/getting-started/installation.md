# Installation

This guide provides instructions for installing Wazuh server and agent components. Before proceeding, verify that your system meets the requirements listed in the [Packages](packages.md) page.

## Server

This section covers single-node and multi-node server installation.

### Installation

Install the Wazuh manager package for your platform:

**Debian-based platforms:**

```bash
sudo dpkg -i wazuh-manager_*.deb
```

**Red Hat-based platforms:**

```bash
sudo rpm -ivh wazuh-manager-*.rpm
```

### Configuration

#### Deploy certificates

Deploy the SSL certificates for secure communication between the Wazuh server and indexer. These certificates should be extracted from the `wazuh-certificates.tar` file generated during the certificate creation process.

```bash
NODE_NAME=node-1

# Create certificates directory
sudo mkdir -p /var/ossec/etc/certs

# Extract and deploy certificates
sudo tar -xf wazuh-certificates.tar -C /var/ossec/etc/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
sudo mv /var/ossec/etc/certs/$NODE_NAME.pem /var/ossec/etc/certs/server.pem
sudo mv /var/ossec/etc/certs/$NODE_NAME-key.pem /var/ossec/etc/certs/server-key.pem

# Set proper permissions
sudo chmod 500 /var/ossec/etc/certs
sudo chmod 400 /var/ossec/etc/certs/*
sudo chown -R wazuh:wazuh /var/ossec/etc/certs
```

**Note:** Replace `node-1` with the name you used when generating the certificates.

#### Configure indexer connection

Configure the Wazuh server to connect to the Wazuh indexer using the secure keystore:

```bash
# Set indexer credentials (default: admin/admin)
sudo /var/ossec/bin/wazuh-keystore -f indexer -k username -v admin
sudo /var/ossec/bin/wazuh-keystore -f indexer -k password -v admin
```

Update the indexer configuration in `/var/ossec/etc/ossec.conf` to specify the indexer IP address:

```xml
<indexer>
  <enabled>yes</enabled>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/var/ossec/etc/certs/root-ca.pem</ca>
    </certificate_authorities>
    <certificate>/var/ossec/etc/certs/server.pem</certificate>
    <key>/var/ossec/etc/certs/server-key.pem</key>
  </ssl>
</indexer>
```

Replace `127.0.0.1` with your indexer IP address if it's running on a different host.

### Start the manager

Start and enable the server service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
```

Verify the server is running:

```bash
sudo systemctl status wazuh-manager
```

### Cluster configuration

The Wazuh server cluster allows you to scale horizontally by distributing the load across multiple nodes. The cluster comes enabled by default with the following configuration in `/var/ossec/etc/ossec.conf`:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>node01</node_name>
  <node_type>master</node_type>
  <key>fd3350b86d239654e34866ab3c4988a8</key>
  <port>1516</port>
  <bind_addr>127.0.0.1</bind_addr>
  <nodes>
      <node>127.0.0.1</node>
  </nodes>
  <hidden>no</hidden>
</cluster>
```

#### Multi-node deployment

For a multi-node cluster deployment, you need to configure one master node and one or more worker nodes. Follow these steps on each node:

1. **On the master node**, edit `/var/ossec/etc/ossec.conf`:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>master-node</node_name>
  <node_type>master</node_type>
  <key>fd3350b86d239654e34866ab3c4988a8</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
      <node>MASTER_NODE_IP</node>
  </nodes>
  <hidden>no</hidden>
</cluster>
```

Replace `MASTER_NODE_IP` with the actual IP address of the master node.

2. **On each worker node**, edit `/var/ossec/etc/ossec.conf`:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>worker-node-01</node_name>
  <node_type>worker</node_type>
  <key>fd3350b86d239654e34866ab3c4988a8</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
      <node>MASTER_NODE_IP</node>
  </nodes>
  <hidden>no</hidden>
</cluster>
```

Replace `MASTER_NODE_IP` with the actual IP address of the master node, and use a unique `node_name` for each worker.

3. **Restart the Wazuh manager service** on all nodes after making configuration changes:

```bash
sudo systemctl restart wazuh-manager
```

4. **Verify the cluster status** from any node:

```bash
sudo /var/ossec/bin/cluster_control -l
```

### Configuration parameters

**`name`**\
Name of the cluster. All nodes must use the same cluster name.

**`node_name`**\
Unique name for each node in the cluster.

**`node_type`**\
Node role, either `master` or `worker`. Only one master node is allowed per cluster.

**`key`**\
Pre-shared key for cluster authentication. All nodes must use the same key.

**`port`**\
Port for cluster communication. Default: `1516`.

**`bind_addr`**\
IP address to bind the cluster listener. Use `0.0.0.0` to listen on all interfaces.

**`nodes`**\
List of master node IP addresses for worker nodes to connect to.

**`hidden`**\
Whether the node is hidden from the cluster. Default: `no`.

## Agent

### Linux

#### Debian-based platforms

```bash
sudo dpkg -i wazuh-agent_*.deb
```

You can optionally specify configuration parameters:

```bash
sudo WAZUH_MANAGER='10.0.0.2' WAZUH_AGENT_NAME='web-server-01' dpkg -i wazuh-agent_*.deb
```

#### Red Hat-based platforms

```bash
sudo rpm -ivh wazuh-agent-*.rpm
```

You can optionally specify configuration parameters:

```bash
sudo WAZUH_MANAGER='10.0.0.2' WAZUH_AGENT_NAME='web-server-01' rpm -ivh wazuh-agent-*.rpm
```

#### SUSE-based platforms

```bash
sudo rpm -ivh wazuh-agent-*.rpm
```

You can optionally specify configuration parameters:

```bash
sudo WAZUH_MANAGER='10.0.0.2' WAZUH_AGENT_NAME='web-server-01' rpm -ivh wazuh-agent-*.rpm
```

#### Starting the agent

After installation, start and enable the agent service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Verify the agent is running:

```bash
sudo systemctl status wazuh-agent
```

### macOS

Install the agent:

```bash
sudo installer -pkg wazuh-agent-*.pkg -target /
```

You can optionally specify configuration parameters:

```bash
sudo WAZUH_MANAGER='10.0.0.2' WAZUH_AGENT_NAME='macbook-01' installer -pkg wazuh-agent-*.pkg -target /
```

Start the agent service:

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/com.wazuh.agent.plist
```

Verify the agent is running:

```bash
sudo /Library/Ossec/bin/wazuh-control status
```

### Windows

Install the agent silently:

```powershell
wazuh-agent-*.msi /q
```

You can optionally specify configuration parameters:

```powershell
wazuh-agent-*.msi /q WAZUH_MANAGER="10.0.0.2" WAZUH_AGENT_NAME="windows-server-01"
```

For interactive installation, double-click the MSI file and follow the installation wizard.

Start the Wazuh Agent service:

```powershell
Start-Service -Name wazuh
```

Verify the agent is running:

```powershell
Get-Service -Name wazuh
```

### Options

#### Server connection

**`WAZUH_MANAGER`**\
Specifies the IP address or hostname of the Wazuh server. The agent uses this to establish communication with the server.

**`WAZUH_MANAGER_PORT`**\
Defines the port used to communicate with the Wazuh server. Default: `1514`.

#### Enrollment configuration

**`WAZUH_REGISTRATION_SERVER`**\
Specifies the IP address or hostname of the enrollment server. When not specified, the value of `WAZUH_MANAGER` is used.

**`WAZUH_REGISTRATION_PORT`**\
Defines the port used for agent enrollment. Default: `1515`.

**`WAZUH_REGISTRATION_PASSWORD`**\
Sets the password required for agent enrollment. This password must match the one configured on the server.

**`WAZUH_REGISTRATION_CA`**\
Specifies the path to the CA certificate used to verify the manager's identity during enrollment.

**`WAZUH_REGISTRATION_CERTIFICATE`**\
Specifies the path to the agent's certificate for enrollment authentication.

**`WAZUH_REGISTRATION_KEY`**\
Specifies the path to the agent's private key for enrollment authentication.

#### Agent identity

**`WAZUH_AGENT_NAME`**\
Sets the agent's name for identification in the Wazuh server. Default: system hostname.

**`WAZUH_AGENT_GROUP`**\
Assigns the agent to a specific group upon enrollment. Default: `default`.

#### Advanced options

**`WAZUH_KEEP_ALIVE_INTERVAL`**\
Defines the interval in seconds between keep-alive messages sent to the server. When not specified, system defaults apply.

**`WAZUH_TIME_RECONNECT`**\
Forces the agent to reconnect to the server every N seconds. Default: disabled.

**`ENROLLMENT_DELAY`**\
Sets a delay in seconds between agent enrollment and the first connection attempt. When not specified, system defaults apply.
