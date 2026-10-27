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

The package refuses to install, even as a fresh installation, on a host that still carries a pre-5.0
manager: an `/etc/ossec-init.conf` of type `server` or `local` naming a version below 5, or a `/var/ossec`
installation that reports itself a server (`wazuh-control info -t`) and whose `VERSION.json` names a version
below 5. A 4.x agent on the same host does not block it. A 4.x manager is not upgraded in place: move to 5.0 as
described in [Migrating a 4.x manager](../../guide/migration/manager-4x-to-5x.md).

#### Installed layout

The manager uses two directories, with no link between them:

| Directory | Holds | Owner:group, mode |
|---|---|---|
| `/etc/wazuh-manager` | `wazuh-manager.conf`, `wazuh-manager-internal-options.conf`, `client.keys`, the agent groups under `shared/`, the enrollment password and token store; `ca/` and `export/`, root's only, hold the manager's CA and what it publishes for the dashboard ([Credentials](credentials.md#files-and-modes)) | `root:wazuh-manager`, `0770` |
| `/etc/wazuh-manager/certs` | every TLS certificate and key the daemons read (see [Credentials and certificates](#credentials-and-certificates)) | `root:wazuh-manager`, `0750`; every file `root:wazuh-manager`, `0640` |
| `/var/wazuh-manager` | binaries, the Server API, databases, queues, logs and detection content | `root:wazuh-manager`, `0750` |

The configuration directory is fixed: a source installation with a custom installation directory
(`USER_DIR`) moves `/var/wazuh-manager` only. A relative path written in `wazuh-manager.conf` still
resolves against the installation directory. No daemon writes `certs/`; only root does (the credential resolver, and `wazuh-manager-certs` for the CA bundle). What
`dpkg --purge` and `rpm -e` remove from each directory is described in [Uninstall](../uninstall.md).

### Installation variables

The `<remote>` block of the generated `/etc/wazuh-manager/wazuh-manager.conf` can be customized at installation time through environment variables. They are honored by the DEB and RPM packages and by the source installer (`install.sh`, also through `etc/preloaded-vars.conf`). When a variable is not set, the default value is used.

```bash
sudo WAZUH_REMOTE_HTTPS_BIND_ADDR='0.0.0.0' WAZUH_REMOTE_HTTPS_PORT='1517' dpkg -i wazuh-manager_*.deb
```

```bash
sudo WAZUH_REMOTE_HTTPS_BIND_ADDR='0.0.0.0' WAZUH_REMOTE_HTTPS_PORT='1517' rpm -ivh wazuh-manager-*.rpm
```

> [!NOTE]
> When using `sudo`, the variables must be placed after `sudo` (as in the examples above) so they reach the package scriptlets. An invalid value aborts a fresh installation with `ERROR: Invalid value '<value>' for installation variable <NAME>: <reason>`, before any configuration is written. A value that passes those checks is then validated with the generated file as a whole, and a fresh installation whose generated `wazuh-manager.conf` the validator refuses is aborted as well (`ERROR: the generated /etc/wazuh-manager/wazuh-manager.conf is not a valid manager configuration.` from the packages).
>
> The variables apply whenever the configuration file is generated. On a fresh installation that is `wazuh-manager.conf`. On an RPM upgrade nothing is generated, so the variables have no effect. On a DEB upgrade the active configuration is never modified, but the variables do shape the regenerated `wazuh-manager.conf.new`; see [Upgrade](../upgrade.md).

| Variable | Configuration option | Default |
|----------|----------------------|---------|
| `WAZUH_REMOTE_HTTPS_PORT` | `remote.https.port` | `1517` |
| `WAZUH_REMOTE_HTTPS_BIND_ADDR` | `remote.https.bind_addr` | `0.0.0.0` |
| `WAZUH_REMOTE_HTTPS_GLOBAL_PREFIX` | `remote.https.global_prefix` | `/wazuh-manager/` |
| `WAZUH_REMOTE_HTTPS_CERTIFICATE` | `remote.https.certificate` | `/etc/wazuh-manager/certs/remoted.pem` |
| `WAZUH_REMOTE_HTTPS_KEY` | `remote.https.key` | `/etc/wazuh-manager/certs/remoted-key.pem` |
| `WAZUH_REMOTE_HTTPS_CA_CERTIFICATE` | `remote.https.ca_certificate` | `/etc/wazuh-manager/certs/root-ca.pem` |
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

`WAZUH_REMOTE_HTTPS_CERTIFICATE` and `WAZUH_REMOTE_HTTPS_KEY` must be provided together. Pointing them anywhere other than the default `/etc/wazuh-manager/certs/remoted.pem`/`remoted-key.pem` opts out of the certificates the manager issues for itself: the referenced files are then provisioned and managed by the administrator (see [Using certificates issued elsewhere](#using-certificates-issued-elsewhere) and [Credentials](credentials.md#certificates)). `WAZUH_REMOTE_HTTPS_VERIFICATION_MODE` values `certificate` and `full` require `WAZUH_REMOTE_HTTPS_CA`.

`WAZUH_REMOTE_HTTPS_GLOBAL_PREFIX` is the URL path every HTTPS endpoint is served under (for example, `/stateless` is exposed as `/wazuh-manager/stateless`). Set it to `/` to serve the endpoints unprefixed. Agents must be configured with the same prefix: the request signature covers the full request path exactly as sent, so a proxy in between must forward it untouched, and a prefix mismatch between agent and manager surfaces as `404`.

> [!IMPORTANT]
> `WAZUH_REMOTE_HTTPS_CERTIFICATE`, `WAZUH_REMOTE_HTTPS_KEY` and `WAZUH_REMOTE_HTTPS_CA_CERTIFICATE` must name files directly in `/etc/wazuh-manager/certs`, given as absolute paths as the defaults are, such as `/etc/wazuh-manager/certs/remoted.crt`. The credential check that runs before every start refuses any other location, a relative path included (it resolves against the installation directory `/var/wazuh-manager`), with `Invalid credentials. Exiting` and `INVALID remote.https.certificate: … is outside /etc/wazuh-manager/certs, the only place the resolver checks …`; it also requires each file to be `root:wazuh-manager` `0640` (`Unsafe credentials. Exiting` otherwise). The credential resolver issues only the default `remoted.pem`/`remoted-key.pem` pair and `root-ca.pem` bundle: a file under another name is yours to provision before the manager is started, and while it is absent the start is refused with `Unresolved credentials. Exiting` (`MISSING …: configured as remote.https.certificate …; stage the pair …`). See [Configured file names](credentials.md#configured-file-names).
>
> `WAZUH_REMOTE_HTTPS_CA` is not checked by the resolver. Give it as an absolute path; a relative one resolves against `/var/wazuh-manager` (every daemon runs with it as its working directory), so `wazuh-manager-remoted` opens a path exactly as `wazuh-manager-conf validate` checked it. Under the systemd unit (`ProtectHome=yes`, `PrivateTmp=yes`) a file under `/home`, `/root`, `/run/user` or the host's `/tmp` is not visible. When the file is missing, `wazuh-manager-control start` refuses to start anything (`(1244): Invalid configuration at '/remote/https/ca': file not found: …`); when it exists but the `wazuh-manager` user cannot read it and `verification_mode` is `certificate` or `full`, `wazuh-manager-remoted` exits at startup (`Cannot start the HTTPS agent listener: …`).

### Configuration

#### Credentials and certificates

The manager sets up every credential it needs with its credential resolver: the two Server API passwords, the
indexer password, its own CA and two server pairs, and its trust in the indexer. It runs when the package is
installed, the only moment the CA is minted and the server pairs are issued, and again before every start, when it
checks everything and completes the passwords and the indexer trust. On a single host where the indexer is already installed there is nothing to configure:
the manager generates what it owns and imports the indexer's CA, client pair and password from
`/etc/wazuh-indexer/export/`. Install order does not matter: what a component could not resolve at install time
is resolved when it starts.

When the indexer runs on another host, give the manager what it cannot invent or import. Copy the indexer's
`ca.pem` and the client pair it issued for this manager (`manager-client.pem`, `manager-client-key.pem`, from the
indexer's `/etc/wazuh-indexer/export/`) into the manager's certificates directory under the names below, and put
the password in `/etc/wazuh-manager/local.env`:

```bash
sudo install -m 0640 -o root -g wazuh-manager ca.pem /etc/wazuh-manager/certs/indexer-ca.pem
sudo install -m 0640 -o root -g wazuh-manager manager-client.pem /etc/wazuh-manager/certs/indexer-connector.pem
sudo install -m 0640 -o root -g wazuh-manager manager-client-key.pem /etc/wazuh-manager/certs/indexer-connector-key.pem
sudo install -m 0600 -o root -g root /dev/null /etc/wazuh-manager/local.env
echo "WAZUH_INDEXER_MANAGER_PASSWORD='<the wazuh-manager password on the indexer>'" \
    | sudo tee /etc/wazuh-manager/local.env > /dev/null
```

The generated Server API passwords are published, readable by root only, in
`/etc/wazuh-manager/export/credentials.env`; the dashboard on the same host reads its own from there.

See **[Credentials](credentials.md)** for every file and key, the password policy, the certificate rules and what
to do when the manager refuses to start.

#### Using certificates issued elsewhere

A distributed deployment, a corporate PKI, cert-manager or Vault all issue the manager's certificates outside the
host. Stage them **before** installing the package, so the install issues nothing, or replace the pairs it issued
afterwards. Staged files are validated at every start and never replaced.

The manager uses two server pairs of its own, issued by one CA, and the indexer's trust:

| File in `/etc/wazuh-manager/certs/` | Content |
|---|---|
| `remoted.pem`, `remoted-key.pem` | the agent listener's chain (a `serverAuth` leaf, followed by its CA) and key, served by `wazuh-manager-remoted` and reused by `wazuh-manager-authd` on port 1515 |
| `apid.pem`, `apid-key.pem` | the Server API's chain (a `serverAuth` leaf, `CA:FALSE`, with a SAN extension, followed by its CA) and key |
| `root-ca.pem` | the agents' CA bundle; must contain the CA in `/etc/wazuh-manager/ca/root-ca.pem` |
| `indexer-ca.pem` | the indexer's CA |
| `indexer-connector.pem`, `indexer-connector-key.pem` | the client pair the indexer issued for this manager (`clientAuth`) and its key |

When your PKI issued the server pairs from an intermediate CA, `apid.pem` carries the leaf followed by the
intermediates, the intermediate that issued the remoted leaf is added to `certs/root-ca.pem` (agents receive that
file alone), and `ca/root-ca.pem` stays the root; see [Server pairs](credentials.md#server-pairs).

The CA that issued the two server pairs goes in `/etc/wazuh-manager/ca/root-ca.pem` (`root:root 0644` in a
`root:root 0700` directory). Its key, `root-ca.key`, is only needed where the manager should issue pairs itself;
without it nothing can be signed on this host. With pairs staged and no CA in `ca/`, the install does not mint a
second one beside them: it reports `MISSING /etc/wazuh-manager/ca/root-ca.pem: stage the CA that issued the pairs`.

```bash
# <node>-remoted.pem, ... stand for the files your PKI issued for this node.
sudo install -d -m 0700 -o root -g root /etc/wazuh-manager/ca
sudo install -m 0644 -o root -g root root-ca.pem /etc/wazuh-manager/ca/root-ca.pem
sudo install -m 0640 -o root -g wazuh-manager root-ca.pem /etc/wazuh-manager/certs/root-ca.pem
sudo install -m 0640 -o root -g wazuh-manager <node>-remoted.pem /etc/wazuh-manager/certs/remoted.pem
sudo install -m 0640 -o root -g wazuh-manager <node>-remoted-key.pem /etc/wazuh-manager/certs/remoted-key.pem
sudo install -m 0640 -o root -g wazuh-manager <node>-apid.pem /etc/wazuh-manager/certs/apid.pem
sudo install -m 0640 -o root -g wazuh-manager <node>-apid-key.pem /etc/wazuh-manager/certs/apid-key.pem
```

If the install already minted a CA before you staged yours, remove `ca/root-ca.key` and
`ca/.wazuh-manager-bootstrap-ca`, put your CA in `ca/root-ca.pem`, and replace `certs/root-ca.pem` and the pairs
as above: the bundle is never rewritten, and pairs issued by the minted CA no longer chain. The next start
publishes the new CA in `/etc/wazuh-manager/export/ca.pem`.

Every file in `/etc/wazuh-manager/certs` is `root:wazuh-manager` `0640`, in a `root:wazuh-manager` `0750`
directory: the daemons read their pairs after dropping privileges, through the group, but cannot replace or loosen
them. To serve another certificate on the API, use other file names in `/etc/wazuh-manager/certs` and point
`https.key` and `https.cert` at them, with the same owner and mode.

Before every start, the credential resolver checks each pair: that it parses, matches its key, is inside its
validity window, is issued by its CA, and (for the indexer client pair) carries `clientAuth`. A problem stops the
start with a line naming the file; see [When the manager does not start](credentials.md#when-the-manager-does-not-start).
Check what a node presents with `openssl x509 -in /etc/wazuh-manager/certs/remoted.pem -noout -text`.

#### Configure the indexer address

Update the `<indexer>` block of `/etc/wazuh-manager/wazuh-manager.conf` with the indexer address.
The credentials are not configured here — they live in the manager's keystore, written by the
credential resolver. The installer generates this block:

```xml
<indexer>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/etc/wazuh-manager/certs/indexer-ca.pem</ca>
    </certificate_authorities>
    <certificate>/etc/wazuh-manager/certs/indexer-connector.pem</certificate>
    <key>/etc/wazuh-manager/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

Replace `127.0.0.1` with your indexer IP address if it's running on a different host. The `<ssl>`
files must stay directly in `/etc/wazuh-manager/certs`, given as absolute paths: a relative path resolves against
the installation directory `/var/wazuh-manager`, and the credential check refuses any file outside `certs/`
([Configured file names](credentials.md#configured-file-names)). See the
[indexer connector configuration](../modules/indexer_connector/configuration.md) for every option.

### Start the manager

On a fresh installation neither the packages nor `install.sh` start or enable the service: you start
it when the deployment is ready. (An upgrade restarts a manager that was running before it.) Set
`USER_AUTO_START="y"` in `etc/preloaded-vars.conf` to have `install.sh` start it anyway. A fresh package
install ends by printing where the Server API passwords are (only when it published them: a resolver run
stopped by an unsafe or invalid entry writes nothing), whether the credential
resolution is incomplete and the command that completes it, and the command to start the service (and to
enable it at boot, when systemd is running).

Every start first validates the configuration file, then checks the credentials and certificates, the files the
configuration names and each daemon's own test, and finally completes the passwords and the indexer credential;
it starts no daemon when any step fails ([the order and the messages](credentials.md#when-the-manager-does-not-start)).

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

If it refuses to start, `wazuh-manager-control` (and so the journal) prints one line ending in `Exiting`:
`wazuh-manager.conf: Configuration error.` or `<daemon>: Configuration error.` for the configuration, or
`Unsafe credentials.`, `Invalid credentials.`, `Unresolved credentials.` or `Cannot check the credentials.` for the
credentials. `/var/wazuh-manager/logs/wazuh-manager.log` records the reason: the `(1244)` verdict naming the
option or file, or `wazuh-manager-control: ERROR: unresolved credentials` (or `unsafe`, `invalid`) followed by
the resolver's lines naming the file or key and what to do. Fix it and start the service again; no reinstall is
needed. See [When the manager does not start](credentials.md#when-the-manager-does-not-start).

### Server API users

The manager ships two Server API users, both linked to the `administrator` role:

| User | Used by |
| ---- | ------- |
| `wazuh` | Operators and automation calling the Server API |
| `wazuh-internal-client` | The Wazuh dashboard, to reach the Server API on port 55000 |

Neither ships with a password. Each is seeded on the first installation with the value supplied
through `WAZUH_MANAGER_API_PASSWORD` / `WAZUH_MANAGER_WUI_PASSWORD`, or with a freshly generated one
when nothing supplies it, and the result is published in `/etc/wazuh-manager/export/credentials.env`. Two
independent installations therefore never share a credential. An already-seeded `rbac.db` is never reseeded, so
changing a supplied value later does not change a password the manager already holds. See
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
and `wazuh-internal-client` has ID `2` (`GET /security/users`). Change `wazuh-internal-client` first: changing a user's
password invalidates every token that user holds, so once `wazuh`'s own password changes the token
obtained below stops working.

```bash
TOKEN=$(curl -s -k -u wazuh:<WAZUH_MANAGER_API_PASSWORD> -X POST "https://localhost:55000/security/user/authenticate?raw=true")
curl -s -k -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"password":"<NEW_WAZUH_MANAGER_WUI_PASSWORD>"}' "https://localhost:55000/security/users/2"
curl -s -k -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"password":"<NEW_WAZUH_MANAGER_API_PASSWORD>"}' "https://localhost:55000/security/users/1"
```

See [Default users](../modules/server-api/authentication.md#default-users) for the `allow_run_as` semantics, the endpoint rules that apply to these reserved users, and [what a password change does and does not do](../modules/server-api/authentication.md#what-a-password-change-does-and-does-not-do).


### Cluster configuration

Every 5.x manager is a cluster node. The installer generates this block in
`/etc/wazuh-manager/wazuh-manager.conf`, with a `<key>` of 32 random hexadecimal characters drawn
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

1. **On the master node**, edit `/etc/wazuh-manager/wazuh-manager.conf`:

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

2. **On each worker node**, edit `/etc/wazuh-manager/wazuh-manager.conf`:

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

> [!NOTE]
> An agent installed without `WAZUH_ENROLLMENT_TOKEN` does not start until it is registered. Register it first, as described in [Installing without a token](#installing-without-a-token).

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

Start the agent service. An agent installed without `WAZUH_ENROLLMENT_TOKEN` does not start until it is registered; register it first, as described in [Installing without a token](#installing-without-a-token).

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

Start the Wazuh Agent service. An agent installed without `WAZUH_ENROLLMENT_TOKEN` does not start until it is registered; register it first with **Manage** > **Enroll** in the agent GUI, or as described in [Installing without a token](#installing-without-a-token).

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

Check from the manager side. The Server API runs on the master node; list the agent by name and look at its `status`, which reads `active` once it is connected (`pending`, `never_connected` or `disconnected` otherwise). `<WAZUH_MANAGER_API_PASSWORD>` is the current password of the `wazuh` user. Until you change it, that is the `WAZUH_MANAGER_API_PASSWORD` line of `/etc/wazuh-manager/export/credentials.env` on the master (see [The published passwords](credentials.md#the-published-passwords)); the file keeps the install-time value, so after a change use the new password:

```bash
TOKEN=$(curl -s -k -u wazuh:<WAZUH_MANAGER_API_PASSWORD> -X POST "https://localhost:55000/security/user/authenticate?raw=true")
curl -s -k -X GET "https://localhost:55000/agents?name=web-server-01&select=id,name,status,ip&pretty=true" \
    -H "Authorization: Bearer $TOKEN"
```

Drop `name=` to list every agent. The dashboard shows the same list under **Endpoints**. See [List agents](../modules/server-api/api-reference.md#list-agents) for the other filters.

### Monitoring the server host

The manager does not monitor the host it runs on. In 4.x it collected that host's logs, file integrity, SCA and inventory as agent `000`; 5.0 has no agent `000`, and `GET /agents` lists only the agents that enrolled. To monitor a server host, install an agent on it. The agent installs in `/var/ossec`, next to the manager in `/var/wazuh-manager`, and enrolls with a token as described above; the address the token names must reach the manager from the host itself. On a Debian-based all-in-one host:

```bash
TOKEN=$(sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address mgr.example.com)
sudo WAZUH_ENROLLMENT_TOKEN="$TOKEN" WAZUH_AGENT_NAME="$(hostname)" dpkg -i wazuh-agent_*.deb
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
```

The agent adds the usage listed in [Requirements](requirements.md#agent) to the host.

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

A package install with no `WAZUH_ENROLLMENT_TOKEN` completes, and the installer records that the agent has nowhere to connect and, when it has no key yet, how to register it:

```console
wazuh-agent: no manager configured [INFO_NO_MANAGER]: WAZUH_ENROLLMENT_TOKEN was not supplied, so the agent does not know where to connect. Enroll it as root before starting it: echo '<TOKEN>' | /var/ossec/bin/wazuh-agent-auth
```

That is the **Package** and **From sources** methods: the agent is installed but not yet registered. A package install leaves the placeholder `<endpoint>MANAGER_IP</endpoint>` (`0.0.0.0:1517/wazuh-manager/` on Windows), and the agent refuses to start with it until it is registered:

```console
wazuh-agentd: ERROR: (4112): Invalid server address found: 'MANAGER_IP'
wazuh-agentd: ERROR: (4128): This agent is not enrolled yet. Enroll it as root before starting it: echo '<TOKEN>' | /var/ossec/bin/wazuh-agent-auth
wazuh-agentd: ERROR: (1215): No client configured. Exiting.
```

Register it with [`wazuh-agent-auth`](../modules/client/README.md#enrolling-or-re-pointing-an-agent), which installs the trust anchor, enrolls, and writes the manager address the token names. Pipe the token into it, then start the agent:

```bash
echo '<TOKEN>' | sudo /var/ossec/bin/wazuh-agent-auth
sudo systemctl start wazuh-agent
```

To read the token from a file instead, pass `--token-file <path>`. `wazuh-agent-auth` never deletes that file, and the token stays usable until it expires, runs out of uses or is revoked, so remove the file once the agent is enrolled.

On macOS the command is `/Library/Ossec/bin/wazuh-agent-auth`. On Windows, use **Manage** > **Enroll** in the agent GUI, or `wazuh-agent-auth.exe --token-file <path>` from the agent's installation folder.

The variables that are not about registration — `WAZUH_AGENT_NAME`, `WAZUH_AGENT_GROUP`, the timers and `WAZUH_SSL_VERIFICATION` — already applied during the install, and the command reads the name and groups back out of `ossec.conf`, so the agent registers with the ones the install set.

### Migrating agents already running

An agent upgraded from 4.x keeps its identity and never enrolls again. A remote upgrade delivers the manager's CA over the upgrade channel. A local Linux package upgrade (`.deb` or `.rpm`) installs it when `WAZUH_ENROLLMENT_TOKEN` is set: the token re-points the manager address, and the agent installs the CA at its first start without enrolling again, keeping its id. Every other deployment variable is ignored on upgrade. Without a token, the upgrade says so, and the agent runs unverified until [`wazuh-agent-auth --token-file <file> --certs-only`](../modules/client/README.md#enrolling-or-re-pointing-an-agent) installs one, keeping its id. See [Trust anchor delivery to legacy agents](../../guide/migration/remote-agent-upgrade.md#trust-anchor-delivery-to-legacy-agents) and the validation checklist on the same page.

> [!NOTE]
> **Manager-side mutual TLS blocks remote upgrades to 5.0.** Finish migrating the fleet before setting `<remote><https><verification_mode>` to anything other than `none`.
