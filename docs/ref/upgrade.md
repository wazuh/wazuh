# Upgrade

This guide provides instructions for upgrading Wazuh server and agent components from a previous version. The upgrade process preserves your existing configuration and only updates the package binaries. The service is automatically restarted during the upgrade.

## Server

**Note:** This upgrade process applies to Wazuh server version 5.0 or later. Upgrading from version 4.x or earlier is not supported using this method.

### Debian-based platforms

Upgrade the package:

```bash
sudo dpkg -i wazuh-manager_*.deb
```

Verify the server is running:

```bash
sudo systemctl status wazuh-manager
```

### Red Hat-based platforms

Upgrade the package:

```bash
sudo rpm -Uvh wazuh-manager-*.rpm
```

Verify the server is running:

```bash
sudo systemctl status wazuh-manager
```

## Agent

**Note:** This upgrade process applies to Wazuh agent version 4.x or later.

### Linux

#### Debian-based platforms

Upgrade the package:

```bash
sudo dpkg -i wazuh-agent_*.deb
```

Verify the agent is running:

```bash
sudo systemctl status wazuh-agent
```

#### Red Hat-based platforms

Upgrade the package:

```bash
sudo rpm -Uvh wazuh-agent-*.rpm
```

Verify the agent is running:

```bash
sudo systemctl status wazuh-agent
```

#### SUSE-based platforms

Upgrade the package:

```bash
sudo rpm -Uvh wazuh-agent-*.rpm
```

Verify the agent is running:

```bash
sudo systemctl status wazuh-agent
```


### macOS

Upgrade the package:

```bash
sudo installer -pkg wazuh-agent-*.pkg -target /
```

Verify the agent is running:

```bash
sudo /Library/Ossec/bin/wazuh-control status
```

### Windows

Upgrade the package:

```powershell
wazuh-agent-*.msi /q
```

Verify the agent is running:

```powershell
Get-Service -Name wazuh
```
