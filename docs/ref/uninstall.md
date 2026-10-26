# Uninstall

This guide provides instructions for uninstalling Wazuh server and agent components. The uninstallation process automatically stops the service before removing the package.

The manager lives in two directories: the installation directory `/var/wazuh-manager` and the
configuration directory `/etc/wazuh-manager` (configuration, `client.keys`, the agent groups under
`shared/`, the certificates under `certs/`, and the credentials: the manager's CA under `ca/` with its private
key, the published passwords under `export/` and your `local.env`). Both belong to the package, and what each
removal command leaves behind is described per platform below. The manager keeps nothing in `/etc/wazuh`.

## Server

### Debian-based platforms

Remove the package and everything it left behind:

```bash
sudo dpkg --purge wazuh-manager
```

`--purge` deletes `/var/wazuh-manager`, `/etc/wazuh-manager` (credentials included) and the `wazuh-manager` user
and group.

To remove the package but keep the configuration files:

```bash
sudo dpkg --remove wazuh-manager
```

`--remove` deletes `queue/` (the wazuh-db databases, `tasks.db`, the keystore), `var/`, `logs/`,
`data/`, `stats/`, `framework/` and the API directory, and keeps `/etc/wazuh-manager` with every file renamed
to `<name>.save`, the agent groups under `shared/` included (only a file whose name contains `shared` keeps
its name); `api.yaml` is kept as `api/configuration/api.yaml.save`. The CA's private key
`ca/root-ca.key.save` and `local.env.save` are among them. The manager never reads a `.save` file; delete those
two when you no longer need them. The user and the group are left untouched.

### Red Hat-based platforms

Remove the package:

```bash
sudo rpm -e wazuh-manager
```

`rpm -e` deletes the `wazuh-manager` user and group and the state directories under `/var/wazuh-manager`
(`queue/`, `var/`, `logs/`, `data/`, `api/`, `bin/` and the rest). Under `/etc/wazuh-manager`, RPM removes the
files the package lists (`wazuh-manager.conf`, `client.keys`, `wazuh-manager-internal-options.conf`,
`shared/agent-template.conf` and the `default` group's files included), and the files it does not own, such as
the certificates under `certs/`, the credentials under `ca/` and `export/`, `local.env` and the files of the
groups you created under `shared/`, are kept renamed to `<name>.save` (only a file whose name contains `shared`
keeps its name). That renaming runs only when `shared/` is still there after the package's own files are
gone, which it is whenever it holds anything the package did not install. Everything kept, in
`/etc/wazuh-manager` and in `/var/wazuh-manager`, is handed to `root:root` with no group or other access,
because the account that owned part of it no longer exists. Back up anything you want to keep before running
it, and delete `/etc/wazuh-manager` and `/var/wazuh-manager` by hand when the leftovers are no longer needed.

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
