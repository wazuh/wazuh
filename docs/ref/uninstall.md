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
and group, and removes the service's boot enablement if you enabled it, so a later installation starts
disabled again. `--remove` keeps that enablement, as it keeps the configuration.

To remove the package but keep the configuration files:

```bash
sudo dpkg --remove wazuh-manager
```

`--remove` deletes `queue/` (the wazuh-db databases, `tasks.db`, the keystore), `var/`, `logs/`,
`data/`, `framework/` and the API directory, and keeps `/etc/wazuh-manager` with every file renamed
to `<name>.save`, the agent groups under `shared/` included (the `default` group's `agent.conf` is kept as
`shared/default/agent.conf.save`; only a file whose name contains `shared` keeps its name); `api.yaml` is
kept as `api/configuration/api.yaml.save`. The database backups under `/var/wazuh-manager/backup/db` are kept
too. The CA's private key
`ca/root-ca.key.save` and `local.env.save` are among them. The manager never reads a `.save` file; delete those
two when you no longer need them. The user and the group are left untouched.

Only the latest `.save` set survives. Each removal first deletes every `.save` file already in
`/etc/wazuh-manager` and `/var/wazuh-manager/api`, then renames the current files. If you reinstall from
this state, the new installation issues its own CA. A later `--remove` then replaces the earlier
`ca/root-ca.key.save` with the new CA's key, with no warning. A reinstall that **fails** does the same before
any new key exists: when dpkg rolls back a failed install (`postrm abort-install`, or `disappear`), the
package script deletes the old `.save` set, `ca/root-ca.key.save` included, and renames whatever is left.
Copy the `.save` files you need (at least `ca/root-ca.key.save` and `local.env.save`) out of
`/etc/wazuh-manager` and `/var/wazuh-manager/api` before you reinstall.

### Red Hat-based platforms

Remove the package:

```bash
sudo rpm -e wazuh-manager
```

`rpm -e` disables the service at boot if you enabled it, and deletes the `wazuh-manager` user and group and the state directories under `/var/wazuh-manager`
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
As on Debian, only the latest `.save` set survives: each erase deletes the `.save` files of an earlier one
before it renames.

### Installed or overlaid from sources

A manager installed with `install.sh` has no package to remove it: `sudo tools/purge_wazuh.sh` (root, no
prompt, run from a source checkout) stops it and deletes `/var/wazuh-manager`, `/etc/wazuh-manager`, the
units and the user. It also removes any Wazuh package and an agent in `/var/ossec`.

An `install.sh` run over a DEB or RPM rewrites the package's own unit in `/usr/lib/systemd/system`.
On a Debian host, an `install.sh` from an earlier build wrote a second copy to
`/etc/systemd/system/wazuh-manager.service` instead. No package owns that copy, so `dpkg --purge` and
`rpm -e` leave it behind, still registering a service for the removed `/var/wazuh-manager`. Delete it after
the removal:

```bash
sudo rm -f /etc/systemd/system/wazuh-manager.service
sudo systemctl daemon-reload
```

Installing a package again also deletes that copy.

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
