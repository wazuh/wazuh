# How to create and install custom WPK packages

A WPK is what a remote agent upgrade installs: a signed, gzip-compressed bundle of files plus an
installer. This directory holds `wpkpack.py`, which builds one. How upgrades are requested and
delivered is described in [Agent Upgrade](../../docs/ref/modules/agent_upgrade/README.md) (agent side
and the `agent_upgrade` CLI) and [Agent upgrades](../../docs/ref/modules/task_manager/agent-upgrades.md)
(manager side).

## Get a X509 certificate and CA

### Create root CA

```
openssl req -x509 -new -nodes -newkey rsa:2048 -keyout wpk_root.key -out wpk_root.pem -batch -days 1825
```

### Create certificate and key

```
openssl req -new -nodes -newkey rsa:2048 -keyout wpkcert.key -out wpkcert.csr -subj '/C=US/ST=CA/O=Wazuh'
```

- `/C=US` is the country.
- `/ST=CA` is the state.
- `/O=Wazuh` is the organization's name.

Sign this certificate with the root CA:

```
openssl x509 -req -days 730 -in wpkcert.csr -CA wpk_root.pem -CAkey wpk_root.key -out wpkcert.pem -CAcreateserial
```

## Compile a package

WPK packages will usually contain a complete agent code, but this is not necessary.

A WPK package must contain an installation program, in binary form or a script in any language
supported by the agent. Canonical WPK packages contain `upgrade.sh` for UNIX or `upgrade.bat` for
Windows, which is also what the manager names as the installer when none is given. The agent unpacks
the package into its `var/upgrade/` directory and runs the installer from there, waiting at most
`execd.request_timeout` seconds (60 by default). The installer must:

1. Fork itself; the parent returns 0 immediately.
2. Restart the agent.
3. Write `var/upgrade/upgrade_result` containing a status number. The restarted agent reports it as
   an event and deletes the file: `0` means success, `1` *intermediate version required*, `2` (or
   anything else) failure. For instance:

```
0
```

### Requirements

- Python with the Cryptography package, which `wpkpack.py` imports.

You may get the Cryptography package using Pip:

```
pip install cryptography
```

### Canonical WPK package example

1. Prepare a directory with the files you want to ship in the package (for example, an agent installation tree containing your own `upgrade.sh`).

2. Install the root CA, only if you want to **overwrite the root CA** with the file you created before:

```
cp path/to/wpk_root.pem <package_dir>/etc/wpk_root.pem
```

3. Change to that directory:

```
cd <package_dir>
```

4. Compile the WPK package. You need your SSL certificate and key:

```
<repository>/tools/agent-upgrade/wpkpack.py output/myagent.wpk path/to/wpkcert.pem path/to/wpkcert.key *
```

The syntax is `wpkpack.py <pack> <cert> <key> <content> [<content> ...]`:

- `output/myagent.wpk` is the name of the output WPK package.
- `path/to/wpkcert.pem` is the path to your SSL certificate.
- `path/to/wpkcert.key` is the path to your SSL certificate's key.
- `*` is the file (or the files and directories) to be included into the WPK package; directories are
  added recursively, with the paths as given.

*Note: this is a mere example. If you want to distribute a WPK package this way you should first clean the directory.*

## Install a custom WPK package

### Install the root CA into the agent

The root CA certificate, or failing that, the certificate used to sign the WPK package, must be
installed in the agent before running an upgrade. Paths below are relative to the agent's
installation directory (`/var/ossec` on Linux).

You have two options:

1. Overwrite the shipped root CA with your certificate. This will prevent your agent from upgrading using WPK packages from Wazuh.

```
cp /path/to/certificate etc/wpk_root.pem
```

2. Add a new certificate in the agent's `ossec.conf`, next to the shipped one:

```
<agent-upgrade>
  <ca_verification>
    <enabled>yes</enabled>
    <ca_store>etc/wpk_root.pem</ca_store>
    <ca_store>/path/to/certificate</ca_store>
  </ca_verification>
</agent-upgrade>
```

The `<ca_store>` list of `<agent-upgrade><ca_verification>` replaces the one the installer writes
under `<active-response>`; see
[Agent Upgrade Configuration](../../docs/ref/modules/agent_upgrade/configuration.md#ca_store).

### Run the upgrade

Copy the WPK package into `/var/wazuh-manager/var/upgrade/` on the manager — on **every** node of a
cluster, since the agent may download it from any of them — then run:

```
/var/wazuh-manager/bin/agent_upgrade -a 001 -f myagent.wpk -x upgrade.sh
```

- `-a`/`--agents 001` specifies one or more agent IDs to upgrade.
- `-f`/`--file myagent.wpk` is the custom WPK package: a bare file name or a path inside
  `/var/wazuh-manager/var/upgrade/`. The command refuses a file that is not there.
- `-x`/`--execute upgrade.sh` is the installer inside the package (default: `upgrade.bat` for Windows
  agents, `upgrade.sh` otherwise).

The command creates the upgrade tasks and returns; agents run the upgrade on their own and no result
comes back to the manager. Every flag is listed in
[Agent Upgrade](../../docs/ref/modules/agent_upgrade/README.md#agent_upgrade).

Output example:

```
Upgrade tasks created for 1 agent(s).
Note: Agents will execute upgrades autonomously. Use agent logs to track progress.
```

## Create a WPK package repository

The manager builds the WPK's URL from the repository, the target version and the agent's platform
(`src/wazuh_modules/task_manager/src/upgrade/repoLayout.cpp`). For target versions v4.9.0 and later:

| Agent | Directory | File name |
|-------|-----------|-----------|
| Windows | `windows/` | `wazuh_agent_<version>_windows.wpk` |
| macOS | `macos/<pkg>/<arch>/` | `wazuh_agent_<version>_macos_<arch>.<pkg>.wpk` |
| Linux | `linux/<pkg>/<arch>/` | `wazuh_agent_<version>_linux_<arch>.<pkg>.wpk` |

- `<version>` carries the leading `v`, for example `v5.0.0`.
- `<pkg>` is `deb` or `rpm` on Linux (from the agent's distribution, or `--package_type`) and `pkg` on
  macOS.
- `<arch>` is the agent's architecture, renamed for `deb` (`x86_64` → `amd64`, `aarch64` → `arm64`)
  and for macOS (`x86_64` → `intel64`, `aarch64` → `arm64`).

For instance:

> linux/deb/amd64/wazuh_agent_v5.0.0_linux_amd64.deb.wpk

Every directory must contain a file named `versions` with one line per WPK it holds: the version, a
space, and the file's SHA-1. The manager picks the line whose version equals the target. For
instance:

```
v5.0.0 0e116931df8edd6f4382f6f918d76bc14d9caf10
v4.14.1 ba45f0fe9ca4b3c3b4c3b42b4a2e647f3e2df4a3
```

## Install a canonical WPK package

In the same way, the root CA certificate must be installed in the agent prior to run an upgrade.

Run this command from the manager:

```
/var/wazuh-manager/bin/agent_upgrade -a 001 -r example.com/repo/
```

- `-a`/`--agents 001` specifies the agent to upgrade.
- `-r`/`--repository example.com/repo/` is your own WPK repository, as host and path; `https://` is
  prepended unless the value already names a scheme (`http://` with `--http`). If omitted,
  `task-manager.wpk_repository` is used, or else `packages.wazuh.com/<major>.x/wpk/` for the target
  version.
- The target version defaults to the manager's own version; choose another with `-v`.
