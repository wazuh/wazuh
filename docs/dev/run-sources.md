# Run from Sources

This guide describes how to install and run Wazuh components built from source code.

## Prerequisites

Before running from sources, ensure you have:
- Built the components as described in [Build from Sources](build-sources.md)
- Root or administrator privileges for installation

## Server

### Installation

Install the server by running the installation script:

```bash
./install.sh
```

Follow the interactive wizard to install the manager.

### Unattended Installation

Alternatively, configure environment variables as described in `etc/preloaded-vars.conf` for an unattended installation:

```bash
USER_LANGUAGE="en" \
USER_NO_STOP="y" \
USER_INSTALL_TYPE="manager" \
USER_DIR="/var/wazuh-manager" \
USER_ENABLE_SYSCHECK="y" \
USER_ENABLE_ROOTCHECK="y" \
USER_WHITE_LIST="n" \
USER_ENABLE_SYSLOG="y" \
USER_ENABLE_AUTHD="y" \
USER_UPDATE="y" \
USER_AUTO_START="n" \
./install.sh
```

### Starting the Server

After installation, start the manager:

```bash
/var/wazuh-manager/bin/wazuh-manager-control start
```

To verify the server is running:

```bash
/var/wazuh-manager/bin/wazuh-manager-control status
```

## Agent for UNIX

### Installation

Run the installation script and follow the wizard:

```bash
./install.sh
```

### Unattended Installation

Alternatively, use environment variables for unattended installation:

```bash
USER_LANGUAGE="en" \
USER_NO_STOP="y" \
USER_INSTALL_TYPE="agent" \
USER_DIR="/var/ossec" \
USER_AGENT_MANAGER_IP="10.0.0.2" \
USER_ENABLE_SYSCHECK="y" \
USER_ENABLE_ROOTCHECK="y" \
USER_ENABLE_ACTIVE_RESPONSE="y" \
USER_CA_STORE="n" \
USER_UPDATE="y" \
./install.sh
```

**Important**: Set `USER_AGENT_MANAGER_IP` to the correct server address.

### Starting the Agent

After installation, start the agent:

```bash
/var/ossec/bin/wazuh-control start
```

To verify the agent is running:

```bash
/var/ossec/bin/wazuh-control status
```

## Agent for Windows

### Requirements

WiX Toolset 3.14 is required to build the Windows installer package.

Download from: https://github.com/wixtoolset/wix3/releases/tag/wix3141rtm

### Build

First, build the Windows agent as described in [Build from Sources](build-sources.md#build-agent-for-windows):

```bash
make -C src TARGET=winagent deps
make -C src TARGET=winagent
```

Copy all files to a Windows machine.

### Generate Installer Package

Navigate to the `src/win32` directory and execute:

```batch
wazuh-installer-build-msi.bat
```

This will generate the MSI installer package.

### Installation

Once the package is generated, install it using the command line with the server address:

```batch
wazuh-agent-*.msi /q WAZUH_MANAGER="10.0.0.2"
```

**Important**: Replace `10.0.0.2` with the correct server IP address.

For more installation options, see the [Installation](../ref/getting-started/installation.md#windows) guide.

### Starting the Agent

Start the Wazuh service on Windows:

```powershell
Start-Service -Name wazuh
```

To verify the service is running:

```powershell
Get-Service -Name wazuh
```

## Configuration

### Server Configuration

The main server configuration file is located at:

```
/var/wazuh-manager/etc/wazuh-manager.conf
```

After modifying the configuration, restart the server:

```bash
/var/wazuh-manager/bin/wazuh-manager-control restart
```

### Agent Configuration

The agent configuration file is located at:

- **UNIX**: `/var/ossec/etc/ossec.conf`
- **Windows**: `C:\Program Files (x86)\ossec-agent\ossec.conf`

After modifying the configuration, restart the agent:

**UNIX**:
```bash
/var/ossec/bin/wazuh-control restart
```

**Windows**:
```powershell
Restart-Service -Name wazuh
```

## Stopping Services

### Server on UNIX

```bash
/var/wazuh-manager/bin/wazuh-manager-control stop
```

### Agent on UNIX

```bash
/var/ossec/bin/wazuh-control stop
```

### Agent on Windows

```powershell
Stop-Service -Name wazuh
```

## Logs

### Server Logs on UNIX

Logs are located in `/var/wazuh-manager/logs/`:

- `wazuh-manager.log` - Main Wazuh log
- `alerts/alerts.log` - Security alerts
- Individual component logs in `/var/wazuh-manager/logs/`

To monitor logs in real-time:

```bash
tail -f /var/wazuh-manager/logs/wazuh-manager.log
```

### Agent Logs on UNIX

Logs are located in `/var/ossec/logs/`:

- `ossec.log` - Main Wazuh log
- `alerts/alerts.log` - Security alerts
- Individual component logs in `/var/ossec/logs/`

To monitor logs in real-time:

```bash
tail -f /var/ossec/logs/ossec.log
```

### Agent Logs on Windows

Logs are located in `C:\Program Files (x86)\ossec-agent\`:

- `ossec.log` - Main agent log

## Troubleshooting

### Service Won't Start

Check the logs for error messages:

```bash
cat /var/ossec/logs/ossec.log
```

Verify the configuration file syntax:

```bash
/var/ossec/bin/wazuh-control configtest
```

### Agent Not Connecting to Server

1. Verify network connectivity:
   ```bash
   ping <server_ip>
   telnet <server_ip> 1514
   ```

2. Check firewall rules allow traffic on port 1514

3. Verify the server address in the agent configuration

4. Check authentication:
   ```bash
   /var/ossec/bin/manage_agents -l
   ```

### Permission Errors

Ensure Wazuh is running with appropriate permissions:

```bash
ls -l /var/ossec/
```

Wazuh typically runs as the `ossec` user.
