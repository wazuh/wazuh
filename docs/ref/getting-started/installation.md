# Installation

This guide provides instructions for installing Wazuh server and agent components. Before proceeding, verify that your system meets the requirements listed in the [Packages](packages.md) page.

## Server

This section covers single-node and multi-node server installation.

### Download package

Download the Wazuh manager package for your platform and version. See the [Package Download](packages.md#package-download) section for available repositories and download instructions.

### Installation

Install the downloaded Wazuh manager package for your platform:

**Debian-based platforms:**

```bash
sudo dpkg -i wazuh-manager_*.deb
```

**Red Hat-based platforms:**

```bash
sudo rpm -ivh wazuh-manager-*.rpm
```

### Installation variables

The `<remote>` block of the generated `/var/wazuh-manager/etc/wazuh-manager.conf` can be customized at installation time through environment variables. They are honored by the DEB and RPM packages and by the source installer (`install.sh`, also through `etc/preloaded-vars.conf`). When a variable is not set, the default value is used.

```bash
sudo WAZUH_REMOTE_HTTPS_BIND_ADDR='0.0.0.0' WAZUH_REMOTE_HTTPS_PORT='1517' dpkg -i wazuh-manager_*.deb
```

```bash
sudo WAZUH_REMOTE_HTTPS_BIND_ADDR='0.0.0.0' WAZUH_REMOTE_HTTPS_PORT='1517' rpm -ivh wazuh-manager-*.rpm
```

> [!NOTE]
> When using `sudo`, the variables must be placed after `sudo` (as in the examples above) so they reach the package scriptlets. An invalid value aborts a fresh installation with an error, before any configuration is written.
>
> The variables apply whenever the configuration file is generated. On a fresh installation that is `wazuh-manager.conf`. On an RPM upgrade nothing is generated, so the variables have no effect. On a DEB upgrade the active configuration is never modified, but the variables do shape the regenerated `wazuh-manager.conf.new`; see [Upgrade](../upgrade.md).

| Variable | Configuration option | Default |
|----------|----------------------|---------|
| `WAZUH_REMOTE_HTTPS_PORT` | `remote.https.port` | `1517` |
| `WAZUH_REMOTE_HTTPS_BIND_ADDR` | `remote.https.bind_addr` | `0.0.0.0` |
| `WAZUH_REMOTE_HTTPS_GLOBAL_PREFIX` | `remote.https.global_prefix` | `/wazuh-manager/` |
| `WAZUH_REMOTE_HTTPS_CERTIFICATE` | `remote.https.certificate` | `etc/certs/remoted.pem` |
| `WAZUH_REMOTE_HTTPS_KEY` | `remote.https.key` | `etc/certs/remoted-key.pem` |
| `WAZUH_REMOTE_HTTPS_CA` | `remote.https.ca` | not set |
| `WAZUH_REMOTE_HTTPS_VERIFICATION_MODE` | `remote.https.verification_mode` | not set (`none`) |
| `WAZUH_REMOTE_HTTPS_CIPHERS` | `remote.https.ciphers` | not set |
| `WAZUH_REMOTE_HTTPS_MAX_BODY_SIZE` | `remote.https.max_body_size` | not set (`20MB`) |
| `WAZUH_REMOTE_HTTPS_DUAL_STACK` | `remote.https.dual_stack` | not set (`no`) |
| `WAZUH_REMOTE_LEGACY_ENABLED` | `remote.legacy.enabled` | `yes` |
| `WAZUH_REMOTE_LEGACY_PORT` | `remote.legacy.port` | `1514` |
| `WAZUH_REMOTE_LEGACY_PROTOCOL` | `remote.legacy.protocol` | `tcp` |
| `WAZUH_REMOTE_LEGACY_LOCAL_IP` | `remote.legacy.local_ip` | `0.0.0.0` |
| `WAZUH_REMOTE_LEGACY_QUEUE_SIZE` | `remote.legacy.queue_size` | `131072` |
| `WAZUH_REMOTE_LEGACY_IPV6` | `remote.legacy.ipv6` | not set (`no`) |
| `WAZUH_REMOTE_LEGACY_RIDS_CLOSING_TIME` | `remote.legacy.rids_closing_time` | not set (`5m`) |
| `WAZUH_REMOTE_LEGACY_CONNECTION_OVERTAKE_TIME` | `remote.legacy.connection_overtake_time` | not set (`60`) |
| `WAZUH_REMOTE_AGENTS_ALLOW_HIGHER_VERSIONS` | `remote.agents.allow_higher_versions` | `no` |

Options marked "not set" are only written to the configuration file when their variable is provided; the value in parentheses is the built-in default applied by `wazuh-manager-remoted`. See the [remoted configuration reference](../modules/remoted/configuration.md) for the meaning and accepted values of each option.

`WAZUH_REMOTE_HTTPS_CERTIFICATE` and `WAZUH_REMOTE_HTTPS_KEY` must be provided together. The installer never generates the listener certificate: whether these keep their defaults or not, the referenced files are provisioned and managed by the administrator (see [Deploy certificates](#deploy-certificates)). `WAZUH_REMOTE_HTTPS_VERIFICATION_MODE` values `certificate` and `full` require `WAZUH_REMOTE_HTTPS_CA`.

`WAZUH_REMOTE_HTTPS_GLOBAL_PREFIX` is the URL path every HTTPS endpoint is served under (for example, `/stateless` is exposed as `/wazuh-manager/stateless`). Set it to `/` to serve the endpoints unprefixed. Agents must be configured with the same prefix: the request signature covers the full request path exactly as sent, so a proxy in between must forward it untouched, and a prefix mismatch between agent and manager surfaces as `404`.

> [!IMPORTANT]
> `WAZUH_REMOTE_HTTPS_CERTIFICATE`, `WAZUH_REMOTE_HTTPS_KEY` and `WAZUH_REMOTE_HTTPS_CA` must be paths relative to the installation directory, such as `etc/certs/remoted.crt`. `wazuh-manager-remoted` chroots to `/var/wazuh-manager` before opening them, so a host-absolute path like `/etc/pki/wazuh/server.crt` passes validation but is opened as `/var/wazuh-manager/etc/pki/wazuh/server.crt` at runtime. The manager fails closed on them: when a file is missing, `wazuh-manager-control start` refuses to start anything (`(1244): Invalid configuration at '/remote/https/certificate': file not found: …`), and when it exists but the `wazuh-manager` user cannot read it, `wazuh-manager-remoted` exits at startup (`Cannot start the HTTPS agent listener: …`). The files must exist and be readable by the `wazuh-manager` user before the manager is started; the installer does not create them, and only fixes the ownership of the default `etc/certs/remoted.pem`/`remoted-key.pem` pair.

### Configuration

#### Deploy certificates

The manager does not generate TLS certificates. Both the material it needs come from the Wazuh installation assistant's certificate tool (`wazuh-certs-tool`), which issues one root CA and a leaf per node from it, and are extracted from the `wazuh-certificates.tar` file generated during the certificate creation process:

- the **indexer connection** (`root-ca.pem`, `indexer-connector.pem`, `indexer-connector-key.pem`), from the manager node's `$NODE_NAME.pem`/`$NODE_NAME-key.pem`;
- the **HTTPS agent listener** served by `wazuh-manager-remoted` (and reused by `wazuh-manager-authd` on port 1515): `remoted.pem`/`remoted-key.pem`, from the node's `$NODE_NAME-remoted.pem`/`$NODE_NAME-remoted-key.pem`. This must be a leaf of the same `root-ca.pem` — the manager serves that CA on `GET /cacerts` and agents pin it — never a self-signed pair.

```bash
NODE_NAME=node-1

# Create certificates directory
sudo mkdir -p /var/wazuh-manager/etc/certs

# Extract and deploy certificates
sudo tar -xf wazuh-certificates.tar -C /var/wazuh-manager/etc/certs/ \
    ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem \
    ./$NODE_NAME-remoted.pem ./$NODE_NAME-remoted-key.pem
sudo mv /var/wazuh-manager/etc/certs/$NODE_NAME.pem /var/wazuh-manager/etc/certs/indexer-connector.pem
sudo mv /var/wazuh-manager/etc/certs/$NODE_NAME-key.pem /var/wazuh-manager/etc/certs/indexer-connector-key.pem
sudo mv /var/wazuh-manager/etc/certs/$NODE_NAME-remoted.pem /var/wazuh-manager/etc/certs/remoted.pem
sudo mv /var/wazuh-manager/etc/certs/$NODE_NAME-remoted-key.pem /var/wazuh-manager/etc/certs/remoted-key.pem

# Set ownership and permissions.
# The installer creates etc/certs as root:wazuh-manager with the sticky bit (1770).
# The indexer trust material is read as root and owned by root:wazuh-manager 0640, so
# the manager can read it after dropping privileges but cannot replace its own trust
# anchor. remoted and authd open the listener pair AFTER dropping privileges, so it is
# owned by wazuh-manager:wazuh-manager 0640 (the installer re-applies this to an already
# deployed pair at the default paths on every install or upgrade).
sudo chown root:wazuh-manager \
    /var/wazuh-manager/etc/certs/root-ca.pem \
    /var/wazuh-manager/etc/certs/indexer-connector.pem \
    /var/wazuh-manager/etc/certs/indexer-connector-key.pem
sudo chown wazuh-manager:wazuh-manager \
    /var/wazuh-manager/etc/certs/remoted.pem \
    /var/wazuh-manager/etc/certs/remoted-key.pem
sudo chmod 640 \
    /var/wazuh-manager/etc/certs/root-ca.pem \
    /var/wazuh-manager/etc/certs/indexer-connector.pem \
    /var/wazuh-manager/etc/certs/indexer-connector-key.pem \
    /var/wazuh-manager/etc/certs/remoted.pem \
    /var/wazuh-manager/etc/certs/remoted-key.pem
```

**Note:** Replace `node-1` with the name you used when generating the certificates.

The listener pair is mandatory and the manager fails closed without it. When it is missing at install time the package prints, once:

```
NOTICE: no TLS certificate for the HTTPS agent listener was found
        (/var/wazuh-manager/etc/certs/remoted.pem, /var/wazuh-manager/etc/certs/remoted-key.pem).
        wazuh-manager does not generate certificates. Provision root-ca.pem,
        remoted.pem and remoted-key.pem with the Wazuh installation assistant
        (wazuh-certs-tool) before starting the service; wazuh-manager-control
        refuses to start until they exist. ...
```

and `wazuh-manager-control start` stops at the configuration validator, before any daemon runs, with the same verdict on the console and in `logs/wazuh-manager.log`:

```
(1244): Invalid configuration at '/remote/https/certificate': file not found: /var/wazuh-manager/etc/certs/remoted.pem (the manager does not generate certificates; provision the file, e.g. with wazuh-certs-tool).
```

A pair that exists but is not readable by the `wazuh-manager` user passes that validator (it runs as root) and stops `wazuh-manager-remoted` instead, which logs `Cannot start the HTTPS agent listener: the TLS private key 'etc/certs/remoted-key.pem' is missing or unreadable by the service user.` (or the certificate, or both) followed by the same provisioning hint, and exits; `wazuh-manager-authd` reports `SSL context setup failed (certificate '…', key '…')` for the same reason. Fix the ownership as above and start again.

#### Configure indexer connection

Configure the Wazuh server to connect to the Wazuh indexer using the secure keystore:

```bash
# Set indexer credentials (default: wazuh-manager/wazuh-manager)
sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k username -v wazuh-manager
sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password -v wazuh-manager
```

Update the indexer configuration in `/var/wazuh-manager/etc/wazuh-manager.conf` to specify the indexer IP address:

```xml
<indexer>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/var/wazuh-manager/etc/certs/root-ca.pem</ca>
    </certificate_authorities>
    <certificate>/var/wazuh-manager/etc/certs/indexer-connector.pem</certificate>
    <key>/var/wazuh-manager/etc/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

Replace `127.0.0.1` with your indexer IP address if it's running on a different host.

### Start the manager

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

### Change the default API passwords

The manager ships two Server API users. Both are linked to the `administrator` role and both are created with a password equal to the username the first time the API starts (`framework/wazuh/rbac/default/users.yaml`):

| User        | Default password | Used by                                                      |
| ----------- | ---------------- | ------------------------------------------------------------ |
| `wazuh`     | `wazuh`          | Operators and automation calling the Server API              |
| `wazuh-wui` | `wazuh-wui`      | The Wazuh dashboard, to reach the Server API on port 55000   |

While a user keeps its shipped password, `wazuh-manager-apid` says so on every start:

```
WARNING: The 'wazuh' API user still has its default password. Anyone able to reach the API can use it.
Change it with '/var/wazuh-manager/bin/rbac_control change-password'
```

Change both right after the first start. A password must be 12 to 64 characters long and contain at least one uppercase letter, one lowercase letter, one digit and one non-alphanumeric character; the API rejects anything else with error `5009` (length) or `5007` (character classes).

Run the following on the **master node**: authentication is always resolved there, so that is the database the API reads. Every node keeps its own `api/configuration/security/rbac.db` and the cluster does not synchronize it, so a worker still holds the shipped defaults; they stay unused while it is a worker, but they become live the moment it is promoted to master. Repeat the change on any node that may take that role.

```bash
sudo /var/wazuh-manager/bin/rbac_control change-password
```

The tool prompts for a new password for each default user and applies them in one run. Press Enter to leave a user unchanged.

```
New password for 'wazuh' (skip):
New password for 'wazuh-wui' (skip):
	wazuh: UPDATED
	wazuh-wui: UPDATED
```

For unattended installs the same command reads the passwords from a file, so they never reach the process list, and exits non-zero if any change was not applied:

```bash
# One user, password read from the first line of a file ('-' reads the standard input)
sudo /var/wazuh-manager/bin/rbac_control change-password --user wazuh-wui --password-file /root/wui.pass

# Both default users in a single execution
echo '{"wazuh": "<NEW_WAZUH_PASSWORD>", "wazuh-wui": "<NEW_WAZUH_WUI_PASSWORD>"}' \
    | sudo /var/wazuh-manager/bin/rbac_control change-password --passwords-file -
```

The same change can be made through the API, which is the option for automation. `wazuh` has ID `1` and `wazuh-wui` has ID `2` (`GET /security/users`). Change `wazuh-wui` first: changing a user's password invalidates every token that user holds, so once `wazuh`'s own password changes the token obtained below stops working.

```bash
TOKEN=$(curl -s -k -u wazuh:wazuh -X POST "https://localhost:55000/security/user/authenticate?raw=true")
curl -s -k -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"password":"<NEW_WAZUH_WUI_PASSWORD>"}' "https://localhost:55000/security/users/2"
curl -s -k -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"password":"<NEW_WAZUH_PASSWORD>"}' "https://localhost:55000/security/users/1"
```

No manager daemon needs a restart: the new password applies to the next authentication, and the tokens of the modified user are revoked at once (`Invalid token`). Tokens held by other users are unaffected. No other manager component uses these accounts, so nothing else on the manager has to be updated.

**If you changed `wazuh-wui`, update the dashboard right away.** This step applies to that user only, on the host where the Wazuh dashboard runs — changing `wazuh` needs nothing here. The dashboard keeps its own copy of the `wazuh-wui` password and cannot reach the API until it matches: every page load fails with `3002 - Request failed with status code 401`. Each of those failures counts as a login attempt on the API, and after `max_login_attempts` (50) the API blocks the dashboard's IP for `block_time` (300 seconds) — the error then becomes `403` and stays that way until the block expires, even after the password is fixed. On a host installed from packages the copy is in `/etc/wazuh-dashboard/opensearch_dashboards.yml`, read once at startup:

```yaml
wazuh_core.hosts:
  default:
    url: https://<MANAGER_IP>
    port: 55000
    username: wazuh-wui
    password: <NEW_WAZUH_WUI_PASSWORD>
    run_as: true
```

```bash
sudo systemctl restart wazuh-dashboard
```

In containers the manager side is the same command through the container runtime — `docker compose exec wazuh.manager /var/wazuh-manager/bin/rbac_control change-password`, or `kubectl exec -n wazuh wazuh-manager-master-0 -- …` — and the dashboard image takes the credential from its `API_USERNAME`/`API_PASSWORD` environment variables (in Kubernetes, the `wazuh-api-cred` Secret), so update those and recreate the dashboard container or roll out the deployment. The RBAC database persists in the manager's `api/configuration` volume.

The installation assistant ships `wazuh-passwords-tool.sh`, which wraps the same API call for one user per run and needs every argument of its API mode:

```bash
bash wazuh-passwords-tool.sh -A -au <API_ADMIN_USER> -ap <API_ADMIN_PASSWORD> -u wazuh-wui -p <NEW_WAZUH_WUI_PASSWORD>
```

It is not a replacement for `rbac_control change-password`: run with `-A` alone it prints its usage and exits `1`, and it changes a single user per invocation. When the user given to `-u` is `wazuh-wui` **and** a Wazuh dashboard is installed on that same host, it also rewrites the dashboard file described above; in every other case that file is left untouched. The tool requires the package layout of a host installation, so it does not apply to the container paths.

See [Default users](../modules/server-api/authentication.md#default-users) for the `allow_run_as` semantics, the endpoint rules that apply to these reserved users, and [what a password change does and does not do](../modules/server-api/authentication.md#what-a-password-change-does-and-does-not-do).

### Cluster configuration

The Wazuh server cluster allows you to scale horizontally by distributing the load across multiple nodes. The cluster comes enabled by default with the following configuration in `/var/wazuh-manager/etc/wazuh-manager.conf`:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>node01</node_name>
  <node_type>master</node_type>
  <key>fd3350b86d239654e34866ab3c4988a8</key>
  <port>1516</port>
  <bind_addr>127.0.0.1</bind_addr>
  <nodes>
      <node>127.0.0.1</node>
  </nodes>
  <hidden>no</hidden>
</cluster>
```

#### Multi-node deployment

For a multi-node cluster deployment, you need to configure one master node and one or more worker nodes. Follow these steps on each node:

1. **On the master node**, edit `/var/wazuh-manager/etc/wazuh-manager.conf`:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>master-node</node_name>
  <node_type>master</node_type>
  <key>fd3350b86d239654e34866ab3c4988a8</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
      <node>MASTER_NODE_IP</node>
  </nodes>
  <hidden>no</hidden>
</cluster>
```

Replace `MASTER_NODE_IP` with the actual IP address of the master node.

2. **On each worker node**, edit `/var/wazuh-manager/etc/wazuh-manager.conf`:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>worker-node-01</node_name>
  <node_type>worker</node_type>
  <key>fd3350b86d239654e34866ab3c4988a8</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
      <node>MASTER_NODE_IP</node>
  </nodes>
  <hidden>no</hidden>
</cluster>
```

Replace `MASTER_NODE_IP` with the actual IP address of the master node, and use a unique `node_name` for each worker.

3. **Restart the Wazuh manager service** on all nodes after making configuration changes:

```bash
sudo systemctl restart wazuh-manager
```

4. **Verify the cluster status** from any node:

```bash
sudo /var/wazuh-manager/bin/cluster_control -l
```

### Configuration parameters

**`name`**\
Name of the cluster. All nodes must use the same cluster name.

**`node_name`**\
Unique name for each node in the cluster.

**`node_type`**\
Node role, either `master` or `worker`. Only one master node is allowed per cluster.

**`key`**\
Pre-shared key for cluster authentication. All nodes must use the same key.

**`port`**\
Port for cluster communication. Default: `1516`.

**`bind_addr`**\
IP address to bind the cluster listener. Use `0.0.0.0` to listen on all interfaces.

**`nodes`**\
List of master node IP addresses for worker nodes to connect to.

**`hidden`**\
Whether the node is hidden from the cluster. Default: `no`.

## Agent

A 5.0 agent registers with an **enrollment token**. The token names the manager, pins the certificate authority that signs the manager's agent-facing certificate, and carries the enrollment credential. Tokens are minted on the manager, see [minting a token](../modules/authd/enrollment-lifecycle.md#step-1-the-operator-mints-a-token) and [Enrollment tokens](../modules/authd/README.md#enrollment-tokens) for listing, revocation and the refusal rules.

A token comes in three shapes, and every installation method below accepts any of them:

| Shape | Minted with | What the agent does with it |
|---|---|---|
| Pinned | the default | Fetches the manager's CA, checks it against the pin in the token, installs it as the trust anchor |
| Embedded CA | `--embed-ca` | Takes the certificate from the token itself; no fetch |
| Credential-less | `--no-credential` | Points the agent at the manager and installs the trust anchor, but presents no enrollment credential |

> [!IMPORTANT]
> Every token expires: 30 days by default, 3650 days at most. Expiry is checked by the manager, not by the installer, so an agent given a stale token installs and starts normally and then fails to register. The agent log names the token id the manager refused.

### Installation methods

| Method | How the agent is installed | How it registers |
|---|---|---|
| **One-line command** | The command the dashboard generates, which carries the token | During the package install |
| **Package** | `dpkg`, `rpm`, `installer` or the MSI | Afterwards, with [`wazuh-agent-auth`](../modules/client/README.md#enrolling-or-re-pointing-an-agent), when the install passed no token |
| **From sources** | `install.sh` | Afterwards, with [`wazuh-agent-auth`](../modules/client/README.md#enrolling-or-re-pointing-an-agent) |

The one-line command comes from the dashboard's *Deploy new agent* page. It sets the deployment variables, downloads the package and installs it. Copy it and run it on the endpoint. The agent name and the groups are optional, as they were before, and are only set when you fill them in.

### Download package

Download the Wazuh agent package for your platform and version. See the [Package Download](packages.md#package-download) section for available repositories and download instructions.

### Linux

#### Debian-based platforms

```bash
sudo dpkg -i wazuh-agent_*.deb
```

The deployment variables below are passed as environment variables, which is what the dashboard's one-line command does:

```bash
sudo WAZUH_ENROLLMENT_TOKEN='<TOKEN>' WAZUH_AGENT_NAME='web-server-01' dpkg -i wazuh-agent_*.deb
```

#### Red Hat-based platforms

```bash
sudo rpm -ivh wazuh-agent-*.rpm
```

```bash
sudo WAZUH_ENROLLMENT_TOKEN='<TOKEN>' WAZUH_AGENT_NAME='web-server-01' rpm -ivh wazuh-agent-*.rpm
```

#### SUSE-based platforms

```bash
sudo rpm -ivh wazuh-agent-*.rpm
```

```bash
sudo WAZUH_ENROLLMENT_TOKEN='<TOKEN>' WAZUH_AGENT_NAME='web-server-01' rpm -ivh wazuh-agent-*.rpm
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

macOS takes its deployment variables from `/tmp/wazuh_envs`, one `NAME='value'` per line. The installer sources that file and then deletes it:

```bash
echo "WAZUH_ENROLLMENT_TOKEN='<TOKEN>'" > /tmp/wazuh_envs && echo "WAZUH_AGENT_NAME='macbook-01'" >> /tmp/wazuh_envs && sudo installer -pkg wazuh-agent-*.pkg -target /
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

The deployment variables are MSI properties:

```powershell
msiexec.exe /i wazuh-agent-*.msi /q WAZUH_ENROLLMENT_TOKEN="<TOKEN>" WAZUH_AGENT_NAME="windows-server-01"
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

#### Enrollment

**`WAZUH_ENROLLMENT_TOKEN`**\
The enrollment token minted on the manager. The only way to register an agent. The installer decodes it, writes the manager address it carries into `<agent><manager><endpoint>`, and stores the token at `etc/enrollment_token` (`0600`, readable only by root; SYSTEM and Administrators only on Windows). The agent consumes it on its first start: it fetches the manager's CA, checks it against the token's pin, installs it as the trust anchor at `etc/certs/root-ca.pem`, enrolls over a fully verified connection, and deletes the token file.

A token install needs no TLS configuration of any kind. The anchor arrives with the token.

A token that cannot be decoded is a **refusal**: nothing is written, the agent keeps the configuration the package shipped, and the reason is logged with a named code — `ERR_BAD_TOKEN` for a token the decoder rejected or one carrying no address, `ERR_NO_DECODER` when the decoder could not be run at all.

#### TLS verification

**`WAZUH_SSL_VERIFICATION`**\
Writes `<agent><ssl><verification_mode>`. Exactly one of `full`, `certificate`, `system` or `none`, matched case-sensitively; any other value is logged and the element is left unset. See [`verification_mode`](../modules/client/configuration.md#verification_mode) for what each mode checks and for the ladder that resolves the mode when this is not set.

Most installs do not need it. A token install resolves to `full` against the anchor it just received, and this variable only overrides that. It matters in two cases: a manager fronted by a publicly trusted certificate, where `system` needs no anchor at all; and an install being configured by hand, where it is the only TLS input a variable can supply.

> [!NOTE]
> In 5.0 this variable is named `WAZUH_SSL_VERIFICATION`. The 4.x spelling `SSL_VERIFICATION` is not read and has no alias.

#### Agent identity

**`WAZUH_AGENT_NAME`**\
Sets the agent's name for identification in the Wazuh server. Writes `<enrollment><agent_name>`. Default: system hostname. Deprecated alias on Windows: `AGENT_NAME`.

**`WAZUH_AGENT_GROUP`**\
Assigns the agent to one or more groups at enrollment, comma-separated. Writes `<enrollment><groups>`. Default: `default`. Deprecated alias: `WAZUH_GROUP` (`GROUP` on Windows).

#### Advanced options

**`WAZUH_KEEP_ALIVE_INTERVAL`**\
Interval in seconds between keep-alive notifications to the manager. Writes `<agent><notify_time>`. Default: `10`. Deprecated alias: `WAZUH_NOTIFY_TIME` (`NOTIFY_TIME` on Windows).

**`WAZUH_TIME_RECONNECT`** *(no effect)*\
Targets `<agent><time-reconnect>`, an option that is deprecated and ignored. Deprecated alias on Windows: `TIME_RECONNECT`.

**`ENROLLMENT_DELAY`**\
Delay in seconds between a successful enrollment and the first connection attempt. Writes `<enrollment><delay_after_enrollment>`. Default: `20`. `0` is rejected by the agent's configuration parser.

#### Variables removed in 5.0

The enrollment token replaced the whole registration family. The names below are still read, so an install carrying a 4.x-era command line or an untouched playbook is told what happened, but none of them writes anything:

```console
wazuh-agent: WAZUH_MANAGER is not supported in 5.0 and was ignored: registration is configured by WAZUH_ENROLLMENT_TOKEN alone; this variable no longer has any effect.
```

| What you used to set | What you set now |
|---|---|
| `WAZUH_MANAGER`, `WAZUH_MANAGER_IP`, `WAZUH_MANAGER_PORT`, `WAZUH_MANAGER_ENDPOINT` | `WAZUH_ENROLLMENT_TOKEN` — the manager address travels inside the token. Without a token, `<agent><manager><endpoint>` in `ossec.conf` |
| `WAZUH_REGISTRATION_PASSWORD`, `WAZUH_PASSWORD` | `WAZUH_ENROLLMENT_TOKEN` — the token carries its own credential, scoped and revocable. No fleet-wide password is written to the endpoint |
| `WAZUH_REGISTRATION_SERVER`, `WAZUH_REGISTRATION_PORT`, `WAZUH_AUTHD_SERVER`, `WAZUH_AUTHD_PORT` | Nothing. Enrollment has used the manager's own HTTPS endpoint since 5.0.0; there is no separate enrollment listener to address |
| `WAZUH_REGISTRATION_CA`, `WAZUH_CERTIFICATE` | Nothing on a token install — the anchor arrives with the token. On a hand-configured install, place the CA at `etc/certs/root-ca.pem` yourself, or name it in `<agent><ssl><certificate_authorities>` |
| `WAZUH_REGISTRATION_CERTIFICATE`, `WAZUH_PEM` | `<agent><ssl><certificate>` in `ossec.conf` |
| `WAZUH_REGISTRATION_KEY`, `WAZUH_KEY` | `<agent><ssl><key>` in `ossec.conf` |
| `SSL_VERIFICATION` | `WAZUH_SSL_VERIFICATION` — renamed, with no alias |

On Windows the same properties are removed under their unprefixed MSI spellings as well: `ADDRESS`, `SERVER_PORT`, `AUTHD_SERVER`, `AUTHD_PORT`, `PASSWORD`, `CERTIFICATE`, `PEM` and `KEY`.

#### Installing without a token

A package install with no `WAZUH_ENROLLMENT_TOKEN` completes, and the installer records that the agent has nowhere to connect:

```console
wazuh-agent: no manager configured [INFO_NO_MANAGER]: WAZUH_ENROLLMENT_TOKEN was not supplied, so the agent does not know where to connect.
```

That is the **Package** and **From sources** methods: the agent is installed but not yet registered. A package install leaves the placeholder `<endpoint>MANAGER_IP</endpoint>`, and the agent refuses to start with it until it is registered:

```console
wazuh-agentd: ERROR: (4112): Invalid server address found: 'MANAGER_IP'
wazuh-agentd: ERROR: (1215): No client configured. Exiting.
```

Register it with [`wazuh-agent-auth`](../modules/client/README.md#enrolling-or-re-pointing-an-agent), which installs the trust anchor, enrolls, and writes the manager address the token names. The variables that are not about registration — `WAZUH_AGENT_NAME`, `WAZUH_AGENT_GROUP`, the timers and `WAZUH_SSL_VERIFICATION` — already applied during the install, and the command reads the name and groups back out of `ossec.conf`, so the agent registers with the ones the install set.

### Migrating agents already running

An agent upgraded from 4.x keeps its identity and never enrolls again, so it needs no token. A remote upgrade delivers the manager's CA over the upgrade channel; a local package upgrade does not, and the agent then runs unverified until [`wazuh-agent-auth --certs-only`](../modules/client/README.md#enrolling-or-re-pointing-an-agent) installs one, keeping its id. See [Trust anchor delivery to legacy agents](../../guide/migration/remote-agent-upgrade.md#trust-anchor-delivery-to-legacy-agents) and the validation checklist on the same page.

> [!NOTE]
> **Manager-side mutual TLS blocks remote upgrades to 5.0.** Finish migrating the fleet before setting `<remote><https><verification_mode>` to anything other than `none`.
