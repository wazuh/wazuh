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

#### Credential variables

Four more variables carry credentials rather than configuration options. They are read on a **fresh installation only**: an upgrade ignores them and keeps what the node already has.

| Variable | What it sets | Required |
|----------|--------------|----------|
| `INDEXER_PASSWORD` | Password of the indexer's `wazuh-manager` user, stored in the keystore | Yes |
| `INDEXER_USERNAME` | Indexer user the manager authenticates as | No, defaults to `wazuh-manager` |
| `INITIAL_WAZUH_PASSWORD` | Password of the `wazuh` Server API user | No, generated when absent |
| `INITIAL_WAZUH_WUI_PASSWORD` | Password of the `wazuh-wui` Server API user | No, generated when absent |

`INDEXER_PASSWORD` is the one the manager cannot invent: the indexer deployment decides it, and there is no default to fall back to. An installation that does not set it still completes and exits `0`, but the node is left **unconfigured**: the Server API passwords it owns are written, the keystore entry it could not resolve is not, the service is left alone, and the report names what is missing:

```
  resolved   Server API passwords for wazuh and wazuh-wui, in /var/wazuh-manager/api/configuration/security/wazuh-preseeded-passwords.yml
  MISSING    indexer password for wazuh-manager, expected in INDEXER_PASSWORD
  The service was not started. To finish:
      https://documentation.wazuh.com/current/installation-guide/wazuh-server/
```

All or nothing: a node missing any credential it consumes stays unconfigured even when it resolved the rest. A manager that starts and then fails every indexer call is harder to diagnose than one that never started and said why. Set the variable and install again.

Unlike the `WAZUH_REMOTE_*` variables above, do not place these after `sudo`: an argument is visible to every account on the host through the process list, and it also lands in the shell history. Export them first and preserve the environment with `sudo -E`:

```bash
read -rs INDEXER_PASSWORD && export INDEXER_PASSWORD
sudo -E apt install wazuh-manager
```

The installation pipes each value into the tool that stores it through its standard input, so none of them reaches a command line either. See [The Server API passwords](#the-server-api-passwords) and [Configure indexer connection](#configure-indexer-connection).

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

#### The Server API passwords

The manager ships no password for its two Server API users, `wazuh` and `wazuh-wui`. The installation generates one for each and writes them to the credentials file, naming it but never the values:

```
  resolved   Server API passwords for wazuh and wazuh-wui, in /var/wazuh-manager/api/configuration/security/wazuh-preseeded-passwords.yml
```

That file is the only disclosure the manager makes. A password reaches neither the installation output, nor the manager log, nor the process list.

To decide the password instead of having it generated, put it in the environment of the installation, in `INITIAL_WAZUH_PASSWORD` for `wazuh` and `INITIAL_WAZUH_WUI_PASSWORD` for `wazuh-wui`. Either one that is absent is generated:

```bash
read -rs INITIAL_WAZUH_PASSWORD && export INITIAL_WAZUH_PASSWORD
read -rs INITIAL_WAZUH_WUI_PASSWORD && export INITIAL_WAZUH_WUI_PASSWORD
sudo -E apt install wazuh-manager
```

A supplied password has to satisfy the API policy, 12 to 64 characters holding both a letter and a digit. One that does not stops the provisioning and names the variable it came from.

**The password is the deployment's, not the node's.** In a cluster, give every node the same pair through those variables, the same way `root-ca.pem` is one file shared by all of them. A node that generates its own would serve a different password the day it is promoted to master, and the dashboard would start answering `401`.

**The credentials file stays.** `api/configuration/security/wazuh-preseeded-passwords.yml` is written `0640`, readable by root and the Wazuh group, and the manager reads it only when it creates `rbac.db`. It is written whether the password was supplied or generated, because it is also how the value reaches the first API start: `rbac.db` is created then, not during the installation, and the installation's environment is gone by the time systemd starts the service. It is kept afterwards so a generated password can still be read, and `wazuh-manager-apid` logs a warning on every start while it is there:

```
WARNING: The API credentials of this node are still in plaintext in '/var/wazuh-manager/api/configuration/security/wazuh-preseeded-passwords.yml'. Store them elsewhere and remove that file. Change them with '/var/wazuh-manager/bin/rbac_control change-password'
```

**Removing it.** Nothing reads the file once `rbac.db` exists, so deleting it costs nothing and is the end of the installation:

```bash
sudo rm /var/wazuh-manager/api/configuration/security/wazuh-preseeded-passwords.yml
```

Do that once the credentials are stored wherever the deployment keeps its secrets, and the warning stops. If you would rather not keep any copy of what the installation wrote, set your own password first and then delete the file. The manager has to be running for this, because it changes the live credential in `rbac.db` rather than the file:

```bash
sudo /var/wazuh-manager/bin/rbac_control change-password --user wazuh
sudo rm /var/wazuh-manager/api/configuration/security/wazuh-preseeded-passwords.yml
```

With `--user` and nothing else the command prompts for that one password without echoing it, so it reaches neither the process list nor the shell history.

Changing `wazuh-wui` this way needs the dashboard configuration updated to match, or it starts answering `401`. See [Changing them](#changing-them).

To pin a password on a node that is already installed but has never started, `bin/rbac_control set-password -u <user>` writes the same file. It reads the value from the first line of the standard input, never from an argument, and merges, so each call provisions one user and keeps the other:

```bash
echo '<password>' | sudo /var/wazuh-manager/bin/rbac_control set-password -u wazuh
```

A user the file does not name is generated when the database is created. Once `rbac.db` exists, neither this command nor the installation changes the password in use, and both say so: `rbac_control change-password` is what changes a live credential.

A file that is present but cannot be used is an installation error, not something to seed around: a section the manager does not read, an entry naming a user that is not a default one, the same user twice, a password the policy rejects, or ownership and permissions that do not hold. The API then stops with error `2012`, leaves no database, and the log names the reason.

#### Configure indexer connection

The manager authenticates against the Wazuh indexer as the indexer's own `wazuh-manager` user. That password is the indexer deployment's, so the manager neither generates it nor ships a default for it: the installation takes it from the `INDEXER_PASSWORD` variable and stores it in the keystore. Without it the installation completes and the node is left unconfigured, as described in [Credential variables](#credential-variables).

```bash
read -rs INDEXER_PASSWORD && export INDEXER_PASSWORD
sudo -E apt install wazuh-manager
```

`read -rs` rather than an assignment on the command line: an argument is visible to every account on the host through the process list, and it would also land in the shell history. From the environment the installation pipes it into `wazuh-manager-keystore` through its standard input, so it reaches no command line either.

`INDEXER_USERNAME` overrides the user name, which defaults to `wazuh-manager`. An upgrade keeps the keystore it already has and does not read either variable.

To change them later, on a manager that is already installed, write the keystore the same way. Do not use the tool's `-v` option, which puts the password on a command line every account on the host can read:

```bash
echo '<password>' | sudo /var/wazuh-manager/bin/wazuh-manager-keystore -f indexer -k password
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

### The API passwords

The manager creates two Server API users the first time the API starts, both linked to the `administrator` role:

| User        | Used by                                                      |
| ----------- | ------------------------------------------------------------ |
| `wazuh`     | Operators and automation calling the Server API              |
| `wazuh-wui` | The Wazuh dashboard, to reach the Server API on port 55000   |

The package ships no password for either of them. What each one ends up with is decided when the manager is installed, and again whenever it has to create `rbac.db`:

- **Supplied**, through `INITIAL_WAZUH_PASSWORD` or `INITIAL_WAZUH_WUI_PASSWORD` at installation time, or written to the credentials file with `rbac_control set-password` before the first start.
- **Generated** otherwise, per user, from the system CSPRNG, satisfying the password policy by construction.

Either way the value lands in `api/configuration/security/wazuh-preseeded-passwords.yml`, and the manager seeds `rbac.db` from it the first time the API starts. See [The Server API passwords](#the-server-api-passwords).

A credentials file that is present but cannot be used is the one case that stops the manager: wrong owner or permissions, malformed YAML, a section this manager does not read, an unknown user, the same user twice, or a password the policy rejects. No database is created and the API refuses to start, which stops the whole manager, since the seeding runs before the daemon forks and `wazuh-manager-control` reads its exit code. The log names the reason, and the file is left on disk to be corrected.

Losing `rbac.db` is recoverable without provisioning anything: the next start seeds it again, from the credentials file if it is still there, and from freshly generated passwords if it is not. In the second case the new passwords have to be propagated to the dashboard, so keep the file, or a copy of what it held, for as long as the deployment depends on those credentials.

An upgrade keeps whatever password the installation already had, because the RBAC migration preserves the default users; a database that cannot be read at all is refused rather than migrated into one whose administrator password nobody knows.

#### Changing them

A password must be 12 to 64 characters long and hold both an alphabetic and a numeric character. That is PCI DSS v4.0 requirement 8.3.6 and nothing else: no rule on case or on symbols, which the requirement does not ask for and which mostly pushes operators towards predictable substitutions. Any character may appear. The maximum is the API's own, not the requirement's. The API answers error `5009` for the length and `5007` for the character classes.

What the manager generates is far above that floor: 32 characters over `A-Z a-z 0-9 . , _ + : @ % ^ = ~ -`, about 198 bits. That alphabet leaves out the quote, backslash, backtick, `$`, `!` and `#`, so a generated password survives a shell command line, a YAML document and a keystore value without being escaped on the way.

Run the following on the **master node**: authentication is always resolved there, so that is the database the API reads. Every node keeps its own `api/configuration/security/rbac.db` and the cluster does not synchronize it. A worker installed with the same `INITIAL_WAZUH_PASSWORD` and `INITIAL_WAZUH_WUI_PASSWORD` as the rest of the deployment seeds those when it is promoted, so promotion does not rotate the credential the dashboard already uses. A worker that was left to generate its own serves a different password the day it is promoted.

A `change-password` only ever reaches the master's own database. Aligning the rest of the cluster is a separate step, and which command it takes depends on the state of each node: see [Server API credentials across nodes](#server-api-credentials-across-nodes).

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

The same change can be made through the API, which is the option for automation. `wazuh` has ID `1` and `wazuh-wui` has ID `2` (`GET /security/users`). Change `wazuh-wui` first: changing a user's password invalidates every token that user holds, so once `wazuh`'s own password changes the token obtained below stops working. `INITIAL_WAZUH_PASSWORD` is `wazuh`'s current password, the one the installation was provisioned with.

```bash
TOKEN=$(curl -s -k -u wazuh:"$INITIAL_WAZUH_PASSWORD" -X POST "https://localhost:55000/security/user/authenticate?raw=true")
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

##### Server API credentials across nodes

The cluster does not synchronize `api/configuration/security/rbac.db`: `cluster.json` shares `etc/`, `etc/shared/` and `var/multigroups/`, and nothing else. Every node holds its own copy, so the Server API passwords are pushed to each one, never replicated.

They still have to match. `wazuh-manager-apid` runs on the master only, so a worker's database is normally never created, but a worker promoted to master serves whatever its own node resolved. If that is not what the dashboard holds, it answers `401`, and `403` once `max_login_attempts` is reached.

How to give a node the deployment's passwords depends on the state it is in:

| State of the node | What to run |
|-------------------|-------------|
| Being installed | Export the same `INITIAL_WAZUH_PASSWORD` and `INITIAL_WAZUH_WUI_PASSWORD` as the rest of the deployment and install with `sudo -E`. Nothing else is needed. |
| Installed, `rbac.db` does not exist yet (a worker, normally) | `rbac_control set-password -u <user>`, once per user, with the manager stopped or running |
| `rbac.db` already exists (it has been master at some point) | `rbac_control change-password --user <user> --local` |

```bash
# A worker that has never seeded: write what it will use if it is ever promoted
echo '<password>' | sudo /var/wazuh-manager/bin/rbac_control set-password -u wazuh
echo '<password>' | sudo /var/wazuh-manager/bin/rbac_control set-password -u wazuh-wui

# A node whose database already exists
sudo /var/wazuh-manager/bin/rbac_control change-password --user wazuh --local
```

> [!IMPORTANT]
> `--local` is not optional on a worker. Without it the call is routed as `local_master` and **executes on the master**, so it changes the master's database while reporting `UPDATED` on the node where it was typed. The worker is left untouched. `rbac_control factory-reset` takes the same option, and without it a reset typed on a worker wipes the master's database instead.

Do not copy `rbac.db` between nodes. It carries the tokens and RBAC resources of the node that created it, not only the passwords.

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
