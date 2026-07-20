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

To uninstall the Wazuh agent, ensure the original Windows installer file is in your working directory and run the following command:

```powershell
msiexec.exe /x wazuh-agent-*.msi /qn
```

Additionally, the Wazuh agent can also be uninstalled without the installer file with the following command:

``` powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* ,
HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName -like "*Wazuh Agent*" } |
ForEach-Object { msiexec.exe /x $_.PSChildName /qn }
```

Finally, the agent can also be uninstalled with this alternative CLI command:

``` powershell
Get-Package -Name "Wazuh Agent" |
Uninstall-Package -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
```

The Wazuh agent is now completely removed from your Windows endpoint.

For interactive uninstallation, use the Windows "Add or Remove Programs" feature.
