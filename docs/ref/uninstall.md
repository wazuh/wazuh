# Uninstall

This guide provides instructions for uninstalling Wazuh server and agent components. The uninstallation process automatically stops the service before removing the package.

## Server

### Debian-based platforms

Remove the package and everything it left behind:

```bash
sudo dpkg --purge wazuh-manager
```

`--purge` deletes `/var/wazuh-manager` and the `wazuh-manager` user and group. It also takes the
manager's own keys out of the managed block of `/etc/wazuh/credentials.env`, and, when neither
`wazuh-indexer` nor `wazuh-dashboard` is still installed, deletes `credentials.env`, the CA directory
`/etc/wazuh/ca` and, if it is then empty, `/etc/wazuh` itself.

To remove the package but keep the configuration files:

```bash
sudo dpkg --remove wazuh-manager
```

`--remove` deletes `queue/` (the wazuh-db databases, `tasks.db`, the keystore), `var/`, `logs/`,
`data/` and the API directory, and keeps `etc/` with every file outside `etc/shared/` renamed to
`<name>.save` (`api.yaml` is kept as `api/configuration/api.yaml.save`). The user, the group and
`/etc/wazuh` are left untouched.

### Red Hat-based platforms

Remove the package:

```bash
sudo rpm -e wazuh-manager
```

`rpm -e` removes the manager's keys from `/etc/wazuh/credentials.env` and, with no `wazuh-indexer` or
`wazuh-dashboard` left, the credentials file and `/etc/wazuh/ca`, as `dpkg --purge` does. It deletes
the `wazuh-manager` user and group and every directory under `/var/wazuh-manager` except `etc/`.
Under `etc/`, RPM removes the files the package lists (`wazuh-manager.conf` and `client.keys`
included), and the files it does not own, such as the certificates under `etc/certs/`, are kept
renamed to `<name>.save`. Back up anything you want to keep before running it, and delete
`/var/wazuh-manager` by hand when the leftovers are no longer needed.

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
# Only present on hosts upgraded from 4.x; a "No receipt" error here is harmless
sudo pkgutil --forget com.wazuh.pkg.wazuh-agent-etc
```

### Windows

To uninstall the Wazuh agent with its installer file, use the same MSI that installed the agent or last upgraded it, and replace `<MSI_PATH>` with its full path. An MSI from another version or build does not match the installed product, and msiexec returns error `1605`. `Start-Process -Wait` returns only when the uninstall finishes, and the command prints the msiexec exit code: `0` or `3010` (restart pending) mean success, and any other value is a [Windows Installer error code](https://learn.microsoft.com/en-us/windows/win32/msi/error-codes).

```powershell
(Start-Process msiexec.exe -ArgumentList '/x "<MSI_PATH>" /qn' -Wait -PassThru).ExitCode
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
