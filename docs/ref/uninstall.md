# Uninstall

This guide provides instructions for uninstalling Wazuh server and agent components. The uninstallation process automatically stops the service before removing the package.

## Server

### Debian-based platforms

Remove the package:

```bash
sudo dpkg --purge wazuh-manager
```

To remove the package but keep configuration files:

```bash
sudo dpkg --remove wazuh-manager
```

### Red Hat-based platforms

Remove the package:

```bash
sudo rpm -e wazuh-manager
```

## Agent

### Linux

#### Debian-based platforms

Remove the package:

```bash
sudo dpkg --purge wazuh-agent
```

To remove the package but keep configuration files:

```bash
sudo dpkg --remove wazuh-agent
```

#### Red Hat-based platforms

Remove the package:

```bash
sudo rpm -e wazuh-agent
```

#### SUSE-based platforms

Remove the package:

```bash
sudo rpm -e wazuh-agent
```

### macOS

Stop the agent service:

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.wazuh.agent.plist
```

Remove the package:

```bash
sudo rm -rf /Library/Ossec
sudo rm -f /Library/LaunchDaemons/com.wazuh.agent.plist
sudo rm -rf /Library/StartupItems/WAZUH
```

Remove the Wazuh user and group:

```bash
sudo dscl . -delete "/Users/wazuh"
sudo dscl . -delete "/Groups/wazuh"
```

Remove from pkgutil:

```bash
sudo pkgutil --forget com.wazuh.pkg.wazuh-agent
```

### Windows

Uninstall the package:

```powershell
msiexec.exe /x wazuh-agent-*.msi /qn
```

For interactive uninstallation, use the Windows "Add or Remove Programs" feature.
