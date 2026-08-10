# Installation

This guide provides instructions for installing Wazuh server and agent components. Before proceeding, verify that your system meets the requirements listed in the [Packages](packages.md) page.

## Server

This section covers single-node and multi-node server installation.

### Download package

Download the Wazuh manager package for your platform and version. See the [Package Download](packages.md#package-download) section for available repositories and download instructions.

### Installation

Install the downloaded Wazuh manager package for your platform:

**Debian-based platforms:**

```bash
sudo dpkg -i wazuh-manager_*.deb
```

**Red Hat-based platforms:**

```bash
sudo rpm -ivh wazuh-manager-*.rpm
```

### Installation variables

The `<remote>` block of the generated `/var/wazuh-manager/etc/wazuh-manager.conf` can be customized at installation time through environment variables. They are honored by the DEB and RPM packages and by the source installer (`install.sh`, also through `etc/preloaded-vars.conf`). When a variable is not set, the default value is used.

```bash
sudo WAZUH_REMOTE_HTTPS_BIND_ADDR='0.0.0.0' WAZUH_REMOTE_HTTPS_PORT='1517' dpkg -i wazuh-manager_*.deb
```

```bash
sudo WAZUH_REMOTE_HTTPS_BIND_ADDR='0.0.0.0' WAZUH_REMOTE_HTTPS_PORT='1517' rpm -ivh wazuh-manager-*.rpm
```

> [!NOTE]
> When using `sudo`, the variables must be placed after `sudo` (as in the examples above) so they reach the package scriptlets. An invalid value aborts a fresh installation with an error, before any configuration is written.
>
> The variables apply whenever the configuration file is generated. On a fresh installation that is `wazuh-manager.conf`. On an RPM upgrade nothing is generated, so the variables have no effect. On a DEB upgrade the active configuration is never modified, but the variables do shape the regenerated `wazuh-manager.conf.new`; see [Upgrade](../upgrade.md).

| Variable | Configuration option | Default |
|----------|----------------------|---------|
| `WAZUH_REMOTE_HTTPS_PORT` | `remote.https.port` | `1517` |
| `WAZUH_REMOTE_HTTPS_BIND_ADDR` | `remote.https.bind_addr` | `127.0.0.1` |
| `WAZUH_REMOTE_HTTPS_CERTIFICATE` | `remote.https.certificate` | `etc/certs/remoted.pem` |
| `WAZUH_REMOTE_HTTPS_KEY` | `remote.https.key` | `etc/certs/remoted-key.pem` |
| `WAZUH_REMOTE_HTTPS_CA` | `remote.https.ca` | not set |
| `WAZUH_REMOTE_HTTPS_VERIFICATION_MODE` | `remote.https.verification_mode` | not set (`none`) |
| `WAZUH_REMOTE_HTTPS_CIPHERS` | `remote.https.ciphers` | not set |
| `WAZUH_REMOTE_HTTPS_MAX_BODY_SIZE` | `remote.https.max_body_size` | not set (`20MB`) |
| `WAZUH_REMOTE_HTTPS_DUAL_STACK` | `remote.https.dual_stack` | not set (`no`) |
| `WAZUH_REMOTE_LEGACY_PORT` | `remote.legacy.port` | `1514` |
| `WAZUH_REMOTE_LEGACY_PROTOCOL` | `remote.legacy.protocol` | `tcp` |
| `WAZUH_REMOTE_LEGACY_LOCAL_IP` | `remote.legacy.local_ip` | `127.0.0.1` |
| `WAZUH_REMOTE_LEGACY_QUEUE_SIZE` | `remote.legacy.queue_size` | `131072` |
| `WAZUH_REMOTE_LEGACY_IPV6` | `remote.legacy.ipv6` | not set (`no`) |
| `WAZUH_REMOTE_LEGACY_RIDS_CLOSING_TIME` | `remote.legacy.rids_closing_time` | not set (`5m`) |
| `WAZUH_REMOTE_LEGACY_CONNECTION_OVERTAKE_TIME` | `remote.legacy.connection_overtake_time` | not set (`60`) |
| `WAZUH_REMOTE_AGENTS_ALLOW_HIGHER_VERSIONS` | `remote.agents.allow_higher_versions` | `no` |

Options marked "not set" are only written to the configuration file when their variable is provided; the value in parentheses is the built-in default applied by `wazuh-manager-remoted`. See the [remoted configuration reference](../modules/remoted/configuration.md) for the meaning and accepted values of each option.

`WAZUH_REMOTE_HTTPS_CERTIFICATE` and `WAZUH_REMOTE_HTTPS_KEY` must be provided together. When they are, the installer does not generate the default self-signed certificate: the referenced files are managed by the administrator. `WAZUH_REMOTE_HTTPS_VERIFICATION_MODE` values `certificate` and `full` require `WAZUH_REMOTE_HTTPS_CA`.

> [!IMPORTANT]
> `WAZUH_REMOTE_HTTPS_CERTIFICATE`, `WAZUH_REMOTE_HTTPS_KEY` and `WAZUH_REMOTE_HTTPS_CA` must be paths relative to the installation directory, such as `etc/certs/remoted.crt`. `wazuh-manager-remoted` chroots to `/var/wazuh-manager` before opening them, so a host-absolute path like `/etc/pki/wazuh/server.crt` passes validation but is opened as `/var/wazuh-manager/etc/pki/wazuh/server.crt` at runtime. When the file is not there, the HTTPS server fails to start and takes the legacy agent listener down with it: the service reports `active` while nothing is listening. The files must exist and be readable by the `wazuh-manager` user before the manager is started; the installer does not create them and does not adjust their ownership.

### Configuration

#### Deploy certificates

Deploy the SSL certificates for secure communication between the Wazuh server and indexer. These certificates should be extracted from the `wazuh-certificates.tar` file generated during the certificate creation process.

```bash
NODE_NAME=node-1

# Create certificates directory
sudo mkdir -p /var/wazuh-manager/etc/certs

# Extract and deploy certificates
sudo tar -xf wazuh-certificates.tar -C /var/wazuh-manager/etc/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
sudo mv /var/wazuh-manager/etc/certs/$NODE_NAME.pem /var/wazuh-manager/etc/certs/indexer-connector.pem
sudo mv /var/wazuh-manager/etc/certs/$NODE_NAME-key.pem /var/wazuh-manager/etc/certs/indexer-connector-key.pem

# Set ownership and permissions on the indexer certificates.
# The installer creates etc/certs as root:wazuh-manager with the sticky bit (1770)
# and the daemons self-generate their own certificates (authd, remoted, apid) there
# as wazuh-manager:wazuh-manager. Only the externally provisioned indexer material is
# owned by root:wazuh-manager 0640, so the manager can read it after dropping
# privileges but cannot replace its own trust anchor.
sudo chown root:wazuh-manager \
    /var/wazuh-manager/etc/certs/root-ca.pem \
    /var/wazuh-manager/etc/certs/indexer-connector.pem \
    /var/wazuh-manager/etc/certs/indexer-connector-key.pem
sudo chmod 640 \
    /var/wazuh-manager/etc/certs/root-ca.pem \
    /var/wazuh-manager/etc/certs/indexer-connector.pem \
    /var/wazuh-manager/etc/certs/indexer-connector-key.pem
```

**Note:** Replace `node-1` with the name you used when generating the certificates.

#### Configure indexer connection

Configure the Wazuh server to connect to the Wazuh indexer using the secure keystore:

```bash
# Set indexer credentials (default: wazuh-manager/wazuh-manager)
sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username -v wazuh-manager
sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password -v wazuh-manager
```

Update the indexer configuration in `/var/wazuh-manager/etc/wazuh-manager.conf` to specify the indexer IP address:

```xml
<indexer>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/var/wazuh-manager/etc/certs/root-ca.pem</ca>
    </certificate_authorities>
    <certificate>/var/wazuh-manager/etc/certs/indexer-connector.pem</certificate>
    <key>/var/wazuh-manager/etc/certs/indexer-connector-key.pem</key>
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

The Wazuh server cluster allows you to scale horizontally by distributing the load across multiple nodes. The cluster comes enabled by default with the following configuration in `/var/wazuh-manager/etc/wazuh-manager.conf`:

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

1. **On the master node**, edit `/var/wazuh-manager/etc/wazuh-manager.conf`:

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

2. **On each worker node**, edit `/var/wazuh-manager/etc/wazuh-manager.conf`:

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
sudo /var/wazuh-manager/bin/cluster_control -l
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

> [!IMPORTANT]
> Enrollment password protection is enabled by default in Wazuh 5.0. Before enrolling agents, you must retrieve the auto-generated password from the manager using:
> 
> ```bash
> sudo cat /var/wazuh-manager/etc/authd.pass
> ```
> 
> Pass this password to the installer using the `WAZUH_REGISTRATION_PASSWORD` environment variable (or `/tmp/wazuh_envs` on macOS, or the installer arguments on Windows) as shown in the examples below.

### Download package

Download the Wazuh agent package for your platform and version. See the [Package Download](packages.md#package-download) section for available repositories and download instructions.

### Linux

#### Debian-based platforms

```bash
sudo dpkg -i wazuh-agent_*.deb
```

You can optionally specify configuration parameters (such as the manager IP and the required registration password):

```bash
sudo WAZUH_MANAGER='10.0.0.2' WAZUH_REGISTRATION_PASSWORD='<PASSWORD>' WAZUH_AGENT_NAME='web-server-01' dpkg -i wazuh-agent_*.deb
```

#### Red Hat-based platforms

```bash
sudo rpm -ivh wazuh-agent-*.rpm
```

You can optionally specify configuration parameters:

```bash
sudo WAZUH_MANAGER='10.0.0.2' WAZUH_REGISTRATION_PASSWORD='<PASSWORD>' WAZUH_AGENT_NAME='web-server-01' rpm -ivh wazuh-agent-*.rpm
```

#### SUSE-based platforms

```bash
sudo rpm -ivh wazuh-agent-*.rpm
```

You can optionally specify configuration parameters:

```bash
sudo WAZUH_MANAGER='10.0.0.2' WAZUH_REGISTRATION_PASSWORD='<PASSWORD>' WAZUH_AGENT_NAME='web-server-01' rpm -ivh wazuh-agent-*.rpm
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

You can optionally specify configuration parameters by writing them to `/tmp/wazuh_envs` before running the installer:

```bash
echo "WAZUH_MANAGER='10.0.0.2'" > /tmp/wazuh_envs && echo "WAZUH_REGISTRATION_PASSWORD='<PASSWORD>'" >> /tmp/wazuh_envs && echo "WAZUH_AGENT_NAME='macbook-01'" >> /tmp/wazuh_envs && sudo installer -pkg wazuh-agent-*.pkg -target /
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
wazuh-agent-*.msi /q WAZUH_MANAGER="10.0.0.2" WAZUH_REGISTRATION_PASSWORD="<PASSWORD>" WAZUH_AGENT_NAME="windows-server-01"
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
Sets the password required for agent enrollment. This password must match the one configured on the server. Enrollment password protection is enabled by default, so retrieve the auto-generated password from the manager before enrolling agents:

```bash
sudo cat /var/wazuh-manager/etc/authd.pass
```

Passing it through this variable is the recommended approach: the installer writes `etc/authd.pass` on the agent and sets its ownership and permissions automatically. See [`use_password`](../modules/authd/configuration.md#use_password) for details and for adding the password to an already-installed agent.

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
