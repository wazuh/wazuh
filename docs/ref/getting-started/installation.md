# Installation

This guide provides instructions for installing Wazuh server and agent components. Before proceeding, verify that your system meets the requirements listed in the [Packages](packages.md) page.

## Server

### Debian-based platforms

```bash
sudo dpkg -i wazuh-manager_*.deb
```

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

### Red Hat-based platforms

```bash
sudo rpm -i wazuh-manager-*.rpm
```

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
