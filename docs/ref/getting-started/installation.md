# Installation

This guide provides instructions for installing Wazuh server and agent components. Before proceeding, verify that your system meets the [Requirements](requirements.md) and that a package exists for your platform ([Packages](packages.md)).

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
> When using `sudo`, the variables must be placed after `sudo` (as in the examples above) so they reach the package scriptlets. An invalid value aborts a fresh installation with `ERROR: Invalid value '<value>' for installation variable <NAME>: <reason>`, before any configuration is written. A value that passes those checks is then validated with the generated file as a whole, and a fresh installation whose generated `wazuh-manager.conf` the validator refuses is aborted as well (`ERROR: the generated /var/wazuh-manager/etc/wazuh-manager.conf is not a valid manager configuration.` from the packages).
>
> The variables apply whenever the configuration file is generated. On a fresh installation that is `wazuh-manager.conf`. On an RPM upgrade nothing is generated, so the variables have no effect. On a DEB upgrade the active configuration is never modified, but the variables do shape the regenerated `wazuh-manager.conf.new`; see [Upgrade](../upgrade.md).

| Variable | Configuration option | Default |
|----------|----------------------|---------|
| `WAZUH_REMOTE_HTTPS_PORT` | `remote.https.port` | `1517` |
| `WAZUH_REMOTE_HTTPS_BIND_ADDR` | `remote.https.bind_addr` | `0.0.0.0` |
| `WAZUH_REMOTE_HTTPS_GLOBAL_PREFIX` | `remote.https.global_prefix` | `/wazuh-manager/` |
| `WAZUH_REMOTE_HTTPS_CERTIFICATE` | `remote.https.certificate` | `etc/certs/remoted.pem` |
| `WAZUH_REMOTE_HTTPS_KEY` | `remote.https.key` | `etc/certs/remoted-key.pem` |
| `WAZUH_REMOTE_HTTPS_CA_CERTIFICATE` | `remote.https.ca_certificate` | `etc/certs/root-ca.pem` |
| `WAZUH_REMOTE_HTTPS_CA` | `remote.https.ca` | not set |
| `WAZUH_REMOTE_HTTPS_VERIFICATION_MODE` | `remote.https.verification_mode` | not set (`certificate` when `WAZUH_REMOTE_HTTPS_CA` is set, `none` otherwise) |
| `WAZUH_REMOTE_HTTPS_CIPHERS` | `remote.https.ciphers` | not set (library default) |
| `WAZUH_REMOTE_HTTPS_MAX_BODY_SIZE` | `remote.https.max_body_size` | not set (`10M`, 10 MiB) |
| `WAZUH_REMOTE_HTTPS_DUAL_STACK` | `remote.https.dual_stack` | not set (`no`) |
| `WAZUH_REMOTE_LEGACY_ENABLED` | `remote.legacy.enabled` | `yes` |
| `WAZUH_REMOTE_LEGACY_PORT` | `remote.legacy.port` | `1514` |
| `WAZUH_REMOTE_LEGACY_PROTOCOL` | `remote.legacy.protocol` | `tcp` |
| `WAZUH_REMOTE_LEGACY_LOCAL_IP` | `remote.legacy.local_ip` | `0.0.0.0` (not written when `WAZUH_REMOTE_LEGACY_IPV6='yes'`, so remoted listens on `::`) |
| `WAZUH_REMOTE_LEGACY_QUEUE_SIZE` | `remote.legacy.queue_size` | `131072` |
| `WAZUH_REMOTE_LEGACY_IPV6` | `remote.legacy.ipv6` | not set (`no`) |
| `WAZUH_REMOTE_LEGACY_RIDS_CLOSING_TIME` | `remote.legacy.rids_closing_time` | not set (`5m`) |
| `WAZUH_REMOTE_LEGACY_CONNECTION_OVERTAKE_TIME` | `remote.legacy.connection_overtake_time` | not set (`60`) |
| `WAZUH_REMOTE_AGENTS_ALLOW_HIGHER_VERSIONS` | `remote.agents.allow_higher_versions` | `no` |

Options marked "not set" are only written to the configuration file when their variable is provided; the value in parentheses is the built-in default applied by `wazuh-manager-remoted`. See the [remoted configuration reference](../modules/remoted/configuration.md) for the meaning and accepted values of each option.

The generated configuration always contains a `<legacy>` block with `<enabled>yes</enabled>`, so an installed manager listens for 4.x agents on port `1514/tcp` as well as on the HTTPS listener (`1517`). That is the installer's choice, not the configuration default: a `<remote>` block with no `<legacy>` block leaves the legacy listener off. Install with `WAZUH_REMOTE_LEGACY_ENABLED='no'`, or set [`legacy.enabled`](../modules/remoted/configuration.md#legacyenabled) to `no` afterwards, for a manager that serves 5.x agents only.

Write `WAZUH_REMOTE_HTTPS_MAX_BODY_SIZE` as the configuration accepts it — a byte count with an optional single-letter suffix (`B`, `K`, `M`, `G`), such as `20M`. The installer's own check also lets a two-letter suffix such as `20MB` through, which the configuration validator then refuses, aborting a fresh installation.

`WAZUH_REMOTE_HTTPS_CERTIFICATE` and `WAZUH_REMOTE_HTTPS_KEY` must be provided together. Pointing them anywhere other than the default `etc/certs/remoted.pem`/`remoted-key.pem` opts out of the certificates the manager issues for itself: the referenced files are then provisioned and managed by the administrator (see [Using certificates issued elsewhere](#using-certificates-issued-elsewhere) and [Credentials](credentials.md#certificates)). `WAZUH_REMOTE_HTTPS_VERIFICATION_MODE` values `certificate` and `full` require `WAZUH_REMOTE_HTTPS_CA`.

`WAZUH_REMOTE_HTTPS_GLOBAL_PREFIX` is the URL path every HTTPS endpoint is served under (for example, `/stateless` is exposed as `/wazuh-manager/stateless`). Set it to `/` to serve the endpoints unprefixed. Agents must be configured with the same prefix: the request signature covers the full request path exactly as sent, so a proxy in between must forward it untouched, and a prefix mismatch between agent and manager surfaces as `404`.

> [!IMPORTANT]
> `WAZUH_REMOTE_HTTPS_CERTIFICATE`, `WAZUH_REMOTE_HTTPS_KEY`, `WAZUH_REMOTE_HTTPS_CA_CERTIFICATE` and `WAZUH_REMOTE_HTTPS_CA` must be paths relative to the installation directory, such as `etc/certs/remoted.crt`. `wazuh-manager-remoted` chroots to `/var/wazuh-manager` before opening them, so a host-absolute path like `/etc/pki/wazuh/server.crt` passes validation but is opened as `/var/wazuh-manager/etc/pki/wazuh/server.crt` at runtime. The manager fails closed on them: when a file is missing, `wazuh-manager-control start` refuses to start anything (`(1244): Invalid configuration at '/remote/https/certificate': file not found: …`), and when it exists but the `wazuh-manager` user cannot read it, `wazuh-manager-remoted` exits at startup (`Cannot start the HTTPS agent listener: …`). The files must exist and be readable by the `wazuh-manager` user before the manager is started. The credential resolver issues the default `etc/certs/remoted.pem`/`remoted-key.pem` pair and fixes its ownership; a pair at any other path is yours to provision.

### Configuration

#### Credentials and certificates

The manager resolves every credential it needs — the two Server API passwords, the indexer service
account, and its own TLS material — through one order, applied when the package is installed and
again immediately before the service starts. There is nothing to configure by hand for a
single-host installation: the packages generate what the manager owns and issue its certificates
from a bootstrap CA.

The certificates are issued **at installation only**. Nothing re-examines or reissues them
afterwards — not a service start, not a package upgrade — so a pair you provision yourself, and the
absence of a CA directory that usually goes with it, survive untouched.

The one credential the manager cannot invent is its account on the indexer, because inventing a
password does not make the peer accept it. Supply it before starting the service:

```bash
sudo install -d -m 0700 -o root -g root /etc/wazuh
sudo touch /etc/wazuh/credentials.env && sudo chmod 0600 /etc/wazuh/credentials.env
echo "WAZUH_INDEXER_MANAGER_PASSWORD='<the wazuh-manager password on the indexer>'" \
    | sudo tee -a /etc/wazuh/credentials.env > /dev/null
```

If the indexer is installed on the same host, it publishes that key itself and there is nothing to
do. Install order does not matter: whatever a component could not resolve at install time is
resolved when it starts.

The generated Server API passwords are in the same file once the manager is installed:

```bash
sudo cat /etc/wazuh/credentials.env
```

Delete the file once every component is installed and running — it holds every plaintext password in
the deployment, and until then it is how the components hand credentials to one another.

See **[Credentials](credentials.md)** for the full resolution order, the password policy, the
certificate flows and what to do when the manager refuses to start.

#### Using certificates issued elsewhere

A distributed deployment, a corporate PKI, cert-manager or Vault all issue the manager's
certificates outside the host. Place them in the manager's own certificates directory along with the
CA that signs them — **before** installing the package, so the install issues nothing, or afterwards,
overwriting the pair it issued. Either way nothing looks at them again.

When the pairs are staged before installing and no CA is in `/etc/wazuh/ca`, the install refuses to
mint a CA beside existing material and prints
`resolve-credentials: the manager has no TLS certificates and this install could not issue them`.
The message is about issuing: the staged pairs stay where they are and are the ones the manager uses.
The `wazuh-manager` user and group do not exist until the package creates them; the package's
post-install step sets the owners and modes shown below on every file of the table that it finds,
before the credential resolver runs.

You do not need to keep a copy of your root CA on the host: `/etc/wazuh/ca` exists so that a manager
given nothing can still come up, and once a pair is in `etc/certs` nothing consults it. If the
install minted a bootstrap CA before you replaced the pair, delete the directory — a signing key on a
node that does not sign is exposure with no purpose:

```bash
sudo rm -rf /etc/wazuh/ca
```

The manager uses three pairs, all of which must be leaves of the same `root-ca.pem`: the HTTPS agent
listener served by `wazuh-manager-remoted` and reused by `wazuh-manager-authd` on port 1515, the
client certificate it presents to the indexer, and the certificate of the Server API
(`wazuh-manager-apid`). Whatever issues them, they go in `etc/certs` under
these names:

| File in `/var/wazuh-manager/etc/certs/` | Content | Owner:group, mode |
|---|---|---|
| `remoted.pem`, `remoted-key.pem` | the certificate chain the agent listener presents (a `serverAuth` leaf; the one the install issues is followed by the CA) and its key | `wazuh-manager:wazuh-manager`, `0640` |
| `indexer-connector.pem`, `indexer-connector-key.pem` | the indexer client leaf (`clientAuth`) and its key | `root:wazuh-manager`, `0640` |
| `apid.pem`, `apid-key.pem` | the Server API certificate chain (a `serverAuth` leaf, `CA:FALSE`, not expired, with a SAN extension; the one the install issues carries the `WAZUH_MANAGER_APID_CERT_SANS` list or the discovered one, and is followed by the CA) and its key | `wazuh-manager:wazuh-manager`, `0640` |
| `root-ca.pem` | the CA all the leaves chain to | `root:wazuh-manager`, `0640` |

```bash
# <node>-remoted.pem, <node>.pem, ... stand for the files your PKI issued for this node.
sudo install -m 0640 -o root -g wazuh-manager root-ca.pem \
    /var/wazuh-manager/etc/certs/root-ca.pem
sudo install -m 0640 -o wazuh-manager -g wazuh-manager <node>-remoted.pem \
    /var/wazuh-manager/etc/certs/remoted.pem
sudo install -m 0640 -o wazuh-manager -g wazuh-manager <node>-remoted-key.pem \
    /var/wazuh-manager/etc/certs/remoted-key.pem
sudo install -m 0640 -o root -g wazuh-manager <node>.pem \
    /var/wazuh-manager/etc/certs/indexer-connector.pem
sudo install -m 0640 -o root -g wazuh-manager <node>-key.pem \
    /var/wazuh-manager/etc/certs/indexer-connector-key.pem
sudo install -m 0640 -o wazuh-manager -g wazuh-manager <node>-apid.pem \
    /var/wazuh-manager/etc/certs/apid.pem
sudo install -m 0640 -o wazuh-manager -g wazuh-manager <node>-apid-key.pem \
    /var/wazuh-manager/etc/certs/apid-key.pem
```

The three pairs do not share an owner. The indexer trust material is root-owned and group-readable, so
the manager reads it after dropping privileges but cannot replace its own trust anchor;
`wazuh-manager-remoted` and `wazuh-manager-authd` open the listener pair after dropping privileges, so
that pair belongs to `wazuh-manager`, and so does the Server API pair. The installer normalizes the
owner of `remoted*` and `apid*` to `wazuh-manager`. To serve another certificate on the API, use other
file names in `etc/certs` and point `https.key` and `https.cert` at them, readable by `wazuh-manager`.

A wrong certificate is not caught at start: nothing re-examines the pair, and no network connection
is opened, so it fails at the first peer connection instead. What *is* caught at start is an
agent-listener file that is missing (`wazuh-manager-conf validate`, with the `(1244)` verdict naming
it) or unreadable by the `wazuh-manager` user (`wazuh-manager-remoted`, after it drops privileges).
`wazuh-manager-apid` loads its own pair at start, after dropping privileges and before daemonizing,
and refuses to start (error `2003` on the terminal and in `logs/api.log`) when it is missing,
unreadable by `wazuh-manager`, mismatched or encrypted. The indexer pair is not checked at start at all — see
[Certificates](credentials.md#issued-at-installation-and-at-no-other-moment). Check what a node
presents with `openssl x509 -in /var/wazuh-manager/etc/certs/remoted.pem -noout -text`.

#### Configure the indexer address

Update the `<indexer>` block of `/var/wazuh-manager/etc/wazuh-manager.conf` with the indexer address.
The credentials are not configured here — they live in the manager's keystore, written by the
credential resolver. The installer generates this block:

```xml
<indexer>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>etc/certs/root-ca.pem</ca>
    </certificate_authorities>
    <certificate>etc/certs/indexer-connector.pem</certificate>
    <key>etc/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

Replace `127.0.0.1` with your indexer IP address if it's running on a different host. The `<ssl>`
paths are relative to `/var/wazuh-manager` unless absolute. See the
[indexer connector configuration](../modules/indexer_connector/configuration.md) for every option.

### Start the manager

On a fresh installation neither the packages nor `install.sh` start or enable the service: you start
it when the deployment is ready. (An upgrade restarts a manager that was running before it.) Set
`USER_AUTO_START="y"` in `etc/preloaded-vars.conf` to have `install.sh` start it anyway. A fresh package
install ends by printing where the Server API passwords are and the command to start the service (and to
enable it at boot, when systemd is running).

Every start first validates the configuration, including that the agent-listener certificate files
exist, and then resolves the passwords and the indexer credential; it starts no daemon when either
step fails.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-manager
```

Verify the server is running:

```bash
sudo systemctl status wazuh-manager
sudo /var/wazuh-manager/bin/wazuh-manager-control status
```

`wazuh-manager-control status` prints one `<daemon> is running...` line per daemon and exits `1` when
any of them is down. `wazuh-manager-apid` is listed only on a master node, and
`wazuh-manager-authd` only when `auth.disabled` is not set.

If it refuses to start, the journal shows `wazuh-manager.conf: Configuration error. Exiting` or `Unresolved credentials. Exiting`, and `/var/wazuh-manager/logs/wazuh-manager.log`
records the reason: the `(1244)` verdict naming the option or file, or
`wazuh-manager-control: ERROR: unresolved credentials` followed by the key that is missing and where
to set it. Fix it and start the service again — there is no reinstall or repair command. See
[When the manager does not start](credentials.md#when-the-manager-does-not-start).

### Server API users

The manager ships two Server API users, both linked to the `administrator` role:

| User | Used by |
| ---- | ------- |
| `wazuh` | Operators and automation calling the Server API |
| `wazuh-wui` | The Wazuh dashboard, to reach the Server API on port 55000 |

Neither ships with a password. Each is seeded on the first installation with the value supplied
through `WAZUH_MANAGER_API_PASSWORD` / `WAZUH_MANAGER_WUI_PASSWORD`, or with a freshly generated one
when nothing supplies it, and the result is written to `/etc/wazuh/credentials.env`. Two independent
installations therefore never share a credential. An already-seeded `rbac.db` is never reseeded, so
editing the file does not change a password the manager already holds. See
[Credentials](credentials.md#the-keys) for the keys and
[the password policy](credentials.md#the-password-policy).

To change one afterwards, run `rbac_control change-password` on any node. It prompts for each
default user (Enter leaves one unchanged) and always applies the change to the **master node's**
database, which is the one the Server API reads: run on a worker, the request is forwarded to the
master. The cluster does not synchronize `rbac.db`, so a node promoted to master later serves its
own: the one it seeded while it was configured as master (the generated configuration makes every
node a master until you change it), or one seeded at its first start as master when it has none. A
password changed with this command is not carried over to it. The file-driven forms are in [Default users](../modules/server-api/authentication.md#default-users).

```bash
sudo /var/wazuh-manager/bin/rbac_control change-password
```

The same change can be made through the API, which is the option for automation. `wazuh` has ID `1`
and `wazuh-wui` has ID `2` (`GET /security/users`). Change `wazuh-wui` first: changing a user's
password invalidates every token that user holds, so once `wazuh`'s own password changes the token
obtained below stops working.

```bash
TOKEN=$(curl -s -k -u wazuh:<WAZUH_PASSWORD> -X POST "https://localhost:55000/security/user/authenticate?raw=true")
curl -s -k -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"password":"<NEW_WAZUH_WUI_PASSWORD>"}' "https://localhost:55000/security/users/2"
curl -s -k -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"password":"<NEW_WAZUH_PASSWORD>"}' "https://localhost:55000/security/users/1"
```

See [Default users](../modules/server-api/authentication.md#default-users) for the `allow_run_as` semantics, the endpoint rules that apply to these reserved users, and [what a password change does and does not do](../modules/server-api/authentication.md#what-a-password-change-does-and-does-not-do).


### Cluster configuration

Every 5.x manager is a cluster node. The installer generates this block in
`/var/wazuh-manager/etc/wazuh-manager.conf`, with a `<key>` of 32 random hexadecimal characters drawn
for each installation (shown here as `GENERATED_KEY`):

```xml
<cluster>
  <name>wazuh</name>
  <node_name>node01</node_name>
  <node_type>master</node_type>
  <key>GENERATED_KEY</key>
  <port>1516</port>
  <bind_addr>127.0.0.1</bind_addr>
  <nodes>
      <node>127.0.0.1</node>
  </nodes>
  <hidden>no</hidden>
</cluster>
```

#### Multi-node deployment

A multi-node cluster has one master node and one or more worker nodes. Because each installation
draws its own key, copy the master's `<key>` to every worker. Before installing the nodes, supply the
same credentials and CA to all of them — see
[Cluster deployments](credentials.md#cluster-deployments).

1. **On the master node**, edit `/var/wazuh-manager/etc/wazuh-manager.conf`:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>master-node</node_name>
  <node_type>master</node_type>
  <key>MASTER_KEY</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
      <node>MASTER_NODE_IP</node>
  </nodes>
  <hidden>no</hidden>
</cluster>
```

Keep the `<key>` the installer generated (shown here as `MASTER_KEY`), and replace `MASTER_NODE_IP`
with the actual IP address of the master node.

2. **On each worker node**, edit `/var/wazuh-manager/etc/wazuh-manager.conf`:

```xml
<cluster>
  <name>wazuh</name>
  <node_name>worker-node-01</node_name>
  <node_type>worker</node_type>
  <key>MASTER_KEY</key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
      <node>MASTER_NODE_IP</node>
  </nodes>
  <hidden>no</hidden>
</cluster>
```

Replace `MASTER_KEY` with the master's key, `MASTER_NODE_IP` with the actual IP address of the master
node, and use a unique `node_name` for each worker.

3. **Restart the Wazuh manager service** on all nodes after making configuration changes:

```bash
sudo systemctl restart wazuh-manager
```

4. **Verify the cluster status** from any node:

```bash
sudo /var/wazuh-manager/bin/cluster_control -l
```

Every option, with its type, default and range, is in the
[cluster configuration reference](../modules/cluster/configuration.md).

## Agent

A 5.0 agent registers with an **enrollment token**. The token names the manager, pins the certificate authority that signs the agent-facing certificate of the manager it was minted on, and carries the enrollment credential. Tokens are minted on the manager (in a cluster, on the master node, whichever node the token's address names). With the manager running, mint one naming the address the agents will connect to:

```bash
sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address mgr.example.com
```

The token is printed on standard output, once: no command retrieves it later. `--address` must be a name in the subject alternative names of the manager's `remote.https.certificate`, and `--port`, `--prefix`, `--ttl`, `--max-uses`, `--description`, `--embed-ca` and `--no-credential` shape the token. See [minting a token](../modules/authd/enrollment-lifecycle.md#step-1-the-operator-mints-a-token) for every check the mint makes, and [Enrollment tokens](../modules/authd/README.md#enrollment-tokens) for listing, revocation and the refusal rules.

A token comes in three shapes, and every installation method below accepts any of them:

| Shape | Minted with | What the agent does with it |
|---|---|---|
| Pinned | the default | Fetches the manager's CA, installs only the certificate that matches the pin in the token as the trust anchor |
| Embedded CA | `--embed-ca` | Installs every CA certificate the token carries as the trust anchor; no fetch |
| Credential-less | `--no-credential` | Points the agent at the manager and installs the trust anchor, but presents no enrollment credential |

In a [CA rotation](../modules/remoted/ca-rotation.md#enrollment-tokens-and-a-rotation) that changes the CA key, pinned tokens minted before the manager's certificates are replaced, and `--embed-ca` tokens minted before the new CA was added, stop working once the certificates are replaced; agents already enrolled with them are not affected. Mint new ones for any still used to enroll agents once every node's certificate has been replaced.

> [!IMPORTANT]
> Every token expires: 30 days by default, 3650 days at most. Expiry is checked by the manager, not by the installer, so an agent given a stale token installs and starts normally and then fails to register. The agent log names the token id the manager refused.

### Installation methods

| Method | How the agent is installed | How it registers |
|---|---|---|
| **One-line command** | The command the dashboard generates, which carries the token | During the package install |
| **Package (Linux/macOS)** | `dpkg`, `rpm` or `installer` | Afterwards, with [`wazuh-agent-auth`](../modules/client/README.md#enrolling-or-re-pointing-an-agent), when the install passed no token |
| **Package (Windows)** | The MSI | Afterwards, from the tray GUI's **Manage** menu (or [`wazuh-agent-auth`](../modules/client/README.md#enrolling-or-re-pointing-an-agent)), when the install passed no token |
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

Shortly after its first connection the agent reloads itself once. It downloads its group's shared configuration from the manager and applies it, and `/var/ossec/logs/ossec.log` records:

```
Agent is reloading due to shared configuration changes.
```

This is expected, not a crash: `systemctl status` shows the reload, and the service stays active. With `<auto_restart>no</auto_restart>` the first reload still happens and logs `Agent is reloading to apply startup hash validated configuration.` instead. See [`auto_restart`](../modules/client/configuration.md#auto_restart).

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

In the commands below, replace `<MSI_PATH>` with the full path of the downloaded MSI (see [Package paths by format](packages.md#package-paths-by-format) for the file name). `Start-Process -Wait` returns only when the installer finishes, and the command prints the msiexec exit code: `0` or `3010` (restart pending) mean success, and any other value is a [Windows Installer error code](https://learn.microsoft.com/en-us/windows/win32/msi/error-codes).

Install the agent silently:

```powershell
(Start-Process msiexec.exe -ArgumentList '/i "<MSI_PATH>" /q' -Wait -PassThru).ExitCode
```

The deployment variables are MSI properties:

```powershell
(Start-Process msiexec.exe -ArgumentList '/i "<MSI_PATH>" /q WAZUH_ENROLLMENT_TOKEN="<TOKEN>" WAZUH_AGENT_NAME="windows-server-01"' -Wait -PassThru).ExitCode
```

For interactive installation, double-click the MSI file and follow the installation wizard.

Start the Wazuh Agent service:

```powershell
Start-Service -Name WazuhSvc
```

Verify the agent is running:

```powershell
Get-Service -Name WazuhSvc
```

#### Module signature verification

The agent verifies the signature of the modules it loads, which requires `Microsoft Identity Verification Root Certificate Authority 2020`, the root Azure Artifact Signing chains to, to be trusted. Windows installs it automatically when the agent first needs it. On endpoints where it cannot (automatic root certificate updates disabled, for example with the `DisableRootAutoUpdate` policy, or old systems without the current root list), the agent logs:

```
The signature of file 'C:\Program Files (x86)\ossec-agent\wazuh-agent.exe' terminated in a root certificate that is not trusted.
The dynamic signature validation is not available because the CA name('Microsoft Identity Verification Root Certificate Authority 2020') is not available.
```

The agent keeps running without module verification. To enable it, install the root in the `Trusted Root Certification Authorities` store of the local computer, as described in [KB5022661](https://support.microsoft.com/en-us/topic/kb5022661-windows-support-for-the-azure-code-signing-program-4b505a31-fa1e-4ea6-85dd-6630229e8ef4); the certificate is available in the [Microsoft PKI repository](https://www.microsoft.com/pkiops/docs/repository.htm). Build options are described in [Package generation](../../dev/package-generation.md#windows-agent-package).

### Verifying the agent connected

Check from the manager side. The Server API runs on the master node; list the agent by name and look at its `status`, which reads `active` once it is connected (`pending`, `never_connected` or `disconnected` otherwise):

```bash
TOKEN=$(curl -s -k -u wazuh:<WAZUH_PASSWORD> -X POST "https://localhost:55000/security/user/authenticate?raw=true")
curl -s -k -X GET "https://localhost:55000/agents?name=web-server-01&select=id,name,status,ip&pretty=true" \
    -H "Authorization: Bearer $TOKEN"
```

Drop `name=` to list every agent. The dashboard shows the same list under **Endpoints**. See [List agents](../modules/server-api/api-reference.md#list-agents) for the other filters.

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

The mode it writes governs the agent's connections once it is enrolled, not the token enrollment itself. That enrollment is always fully verified against the token's CA, the one it embeds or the one it pins, whatever this variable says, so `none` does not let an agent enroll with a manager whose certificate the token's CA does not vouch for. An agent with an explicit `none` says so before it enrolls, with `(4127)`.

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
