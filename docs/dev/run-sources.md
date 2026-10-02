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
USER_INSTALL_TYPE="manager" \
USER_DIR="/var/wazuh-manager" \
USER_ENABLE_AUTHD="y" \
USER_UPDATE="y" \
USER_AUTO_START="n" \
./install.sh
```

### Installing into a Sandbox Directory

`install.sh` registers the system service (`systemctl start wazuh-manager`, or
`service wazuh-manager start` on SysV hosts) for the directory it installs into.
When a service definition already exists and names a *different* directory, the
installer leaves it alone and warns instead of repointing it, so a throwaway
install cannot take over the service of the real installation.

For a sandbox install next to an existing one, skip the boot integration
explicitly and drive the sandbox through its own control script:

```bash
USER_LANGUAGE="en" \
USER_INSTALL_TYPE="manager" \
USER_DIR="/tmp/clean_env/wazuh-manager" \
USER_CLEANINSTALL="y" \
USER_DELETE_DIR="y" \
USER_REGISTER_SERVICE="n" \
./install.sh

/tmp/clean_env/wazuh-manager/bin/wazuh-manager-control start
```

To move the system service to the new directory on purpose, pass
`USER_TAKEOVER_SERVICE="y"` instead.

### Provision certificates

`install.sh` resolves the manager's credentials at the end of the run: it seeds the
Server API passwords, stores the indexer credential if one was supplied, and issues
both TLS pairs under `etc/certs` from a bootstrap CA in `/etc/wazuh/ca`. So a plain
source install already has certificates and you can skip this section.

Two cases where you supply them instead:

* You want the pairs your deployment actually uses (an E2E environment, a node that
  has to match certificates issued elsewhere).
* You passed `USER_RESOLVE_CREDENTIALS="n"` — which you should for any install whose
  tree is copied somewhere else, since a bootstrap CA private key generated once and
  shared by every copy is worse than no certificate at all.

Deploy under `etc/certs` the indexer trust material — `root-ca.pem`,
`indexer-connector.pem`, `indexer-connector-key.pem` (`root:wazuh-manager 640`) — and
the HTTPS agent listener pair — `remoted.pem`, `remoted-key.pem`
(`wazuh-manager:wazuh-manager 640`) — issued by the Wazuh installation assistant's
certificate tool (`wazuh-certs-tool`). Nothing re-examines them afterwards: overwriting
a resolved pair is enough, and the CA directory can go with it. Until they exist,
`wazuh-manager-control start` refuses to start
(`(1244): Invalid configuration at '/remote/https/certificate': file not found: …`).
See [Deploy certificates](../ref/getting-started/installation.md#using-certificates-issued-elsewhere)
and [Credentials](../ref/getting-started/credentials.md).

In the devcontainer, the E2E environment carries a copy of that tool
(`tools/devContainer/scripts/wazuh-certs-tool.sh`, driven by
`wazuh-certs-tool.yml` next to it) and a script that deploys its output with the
names and ownership above:

```bash
cd $WAZUH_REPO/tools/devContainer/e2e
./init.sh --certs-only          # issues certs/ (reuses certs/root-ca.pem when present)
sudo ./wazuh_copy_certs.sh      # -> /var/wazuh-manager/etc/certs
```

For a sandbox install, point the copy script at its directory:

```bash
sudo WAZUH_MANAGER_HOME=/tmp/clean_env/wazuh-manager ./wazuh_copy_certs.sh
```

Or run the tool directly and `install` the five files yourself, as the CI does
(`.github/workflows/5_testintegration_manager.yml`, step "Provision TLS certificates"):

```bash
bash $WAZUH_REPO/tools/devContainer/scripts/wazuh-certs-tool.sh -A -c certs.yml -o ./certs
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
USER_INSTALL_TYPE="agent" \
USER_DIR="/var/ossec" \
USER_AGENT_MANAGER_IP="10.0.0.2" \
USER_ENABLE_ACTIVE_RESPONSE="y" \
USER_CA_STORE="n" \
USER_UPDATE="y" \
./install.sh
```

**Important**: Set `USER_AGENT_MANAGER_IP` (or `USER_AGENT_MANAGER_NAME` for a host name) to the manager address. The installer writes it into `<agent><manager><endpoint>`.

### Enrolling the Agent

A source install does not register the agent. Mint an enrollment token on the manager (`sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address <host>`), save it to a file on the agent, and enroll with `wazuh-agent-auth`, which installs the manager's CA as the trust anchor, registers the agent and writes the address the token names:

```bash
sudo /var/ossec/bin/wazuh-agent-auth --token-file /root/token
```

See [Enrolling or re-pointing an agent](../ref/modules/client/README.md#enrolling-or-re-pointing-an-agent) for the other actions and options.

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

WiX Toolset v3 is required to build the Windows installer package (`candle.exe` and `light.exe`). `wazuh-installer-build-msi.bat` adds `C:\Program Files (x86)\WiX Toolset v3.11\bin` to `PATH`; with another 3.x release installed elsewhere, put its `bin` directory on `PATH` first.

Download from: https://github.com/wixtoolset/wix3/releases

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
wazuh-installer-build-msi.bat <version> <revision>
```

The script asks for the version and the revision when they are not given, and generates `wazuh-agent-<version>-<revision>.msi`. It then signs the package with `signtool sign /a`, which fails without a code-signing certificate available; the MSI is generated before that step either way.

### Installation

Once the package is generated, install it from the same `src/win32` directory with an enrollment token. Replace `<VERSION>` and `<REVISION>` with the values given to the build script, which names the package `wazuh-agent-<VERSION>-<REVISION>.msi`. `start /wait` returns only when the installer finishes:

```batch
start /wait msiexec.exe /i wazuh-agent-<VERSION>-<REVISION>.msi /q WAZUH_ENROLLMENT_TOKEN="<TOKEN>"
```

**Important**: Replace `<TOKEN>` with an enrollment token minted on the manager (`sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address <host>`). The token carries the manager address, so no separate address property is needed. `WAZUH_MANAGER` and `WAZUH_REGISTRATION_PASSWORD` were removed in 5.0: they are ignored, and an install without a token completes with no manager configured.

For more installation options, see the [Installation](../ref/getting-started/installation.md#windows) guide.

### Starting the Agent

Start the Wazuh service on Windows:

```powershell
Start-Service -Name WazuhSvc
```

To verify the service is running:

```powershell
Get-Service -Name WazuhSvc
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
Restart-Service -Name WazuhSvc
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
Stop-Service -Name WazuhSvc
```

## Logs

### Server Logs on UNIX

Logs are located in `/var/wazuh-manager/logs/`:

- `wazuh-manager.log` - Log of every C/C++ daemon
- `wazuh-manager.json` - The same log, in JSON
- `api.log` - Server API log
- `cluster.log` - Cluster daemon log

To monitor logs in real-time:

```bash
tail -f /var/wazuh-manager/logs/wazuh-manager.log
```

### Agent Logs on UNIX

Logs are located in `/var/ossec/logs/`:

- `ossec.log` - Main agent log
- `ossec.json` - The same log, in JSON

To monitor logs in real-time:

```bash
tail -f /var/ossec/logs/ossec.log
```

### Agent Logs on Windows

Logs are located in `C:\Program Files (x86)\ossec-agent\`:

- `ossec.log` - Main agent log

## Troubleshooting

### Manager Won't Start

`wazuh-manager-control start` validates the configuration and resolves the credentials before starting any daemon, and appends the reason it refused to `/var/wazuh-manager/logs/wazuh-manager.log`. Check the configuration on its own with:

```bash
sudo /var/wazuh-manager/bin/wazuh-manager-conf validate
```

### Agent Won't Start

Check the logs for error messages:

```bash
cat /var/ossec/logs/ossec.log
```

Verify the configuration file syntax:

```bash
/var/ossec/bin/wazuh-agentd -t
```

### Agent Not Connecting to Server

1. Verify network connectivity to the manager's agent listener (HTTPS, port 1517 by default):
   ```bash
   curl -sk https://<server_ip>:1517/wazuh-manager/
   ```

2. Check firewall rules allow traffic on port 1517

3. Verify the address in `<agent><manager><endpoint>` of the agent configuration

4. Check the agent is enrolled (it holds a key in `/var/ossec/etc/client.keys`), and list it from the manager's side with the Server API, as described in [Verifying the agent connected](../ref/getting-started/installation.md#verifying-the-agent-connected)

### Permission Errors

Ensure the agent files keep their ownership:

```bash
ls -l /var/ossec/
```

The agent daemons run as the `wazuh` user; the manager daemons run as `wazuh-manager`.
