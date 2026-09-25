# Credentials

The manager resolves every credential it needs through one order, applied when the package is
installed and again immediately before the service starts. Nothing an operator can skip stands
between a deployment and credentials unique to it.

Certificates are the exception, and it is worth knowing up front: they are issued **once, at
installation**, and nothing examines them again — not a service start, not a package upgrade. See
[Certificates](#certificates).

## The resolution order

For each credential, in order:

1. **Already in the manager's own store** — leave it untouched.
2. **A key is set**, in `/etc/wazuh/credentials.env` or in the environment (the environment wins) —
   validate it, then use it.
3. **The manager owns it** — generate a value and publish the key back to the shared file, so a
   component installed later finds it.
4. **None of the above** — the credential is unresolved.

An invalid value does not fall through. If step 2 finds a value that fails validation, resolution
stops there rather than continuing to step 3: falling back to generation would discard your intent
silently and leave the deployment holding a credential nobody else has.

## The keys

| Key | Account | The manager… |
|-----|---------|--------------|
| `WAZUH_MANAGER_API_PASSWORD` | `wazuh` (Server API, in `rbac.db`) | **owns** it — generates one if you do not supply it, and publishes it |
| `WAZUH_MANAGER_WUI_PASSWORD` | `wazuh-wui` (Server API, read by the dashboard) | **owns** it — generates one if you do not supply it, and publishes it |
| `WAZUH_INDEXER_MANAGER_PASSWORD` | `wazuh-manager` (on the indexer) | **consumes** it — never generates it, never publishes it |
| `WAZUH_MANAGER_CERT_SANS` | the indexer-connector certificate | **owns** it |
| `WAZUH_MANAGER_REMOTED_CERT_SANS` | the agent-listener certificate | **owns** it |
| `WAZUH_CA_DIR` | trust material, default `/etc/wazuh/ca` | path only, not a secret |

A credential the manager *owns* lives in its own datastore, so generating one makes it true. A
credential it *consumes* authenticates to somebody else, so inventing one would not make the peer
accept it — which is why `WAZUH_INDEXER_MANAGER_PASSWORD` can only ever be supplied, and why it is
the one key that commonly leaves a fresh manager unresolved until the indexer publishes it.

## The credentials file

`/etc/wazuh/credentials.env` is shared by the manager, the indexer and the dashboard. It is at once
the input, the handoff between components, and the record you read to find a generated password.

* `0600 root:root`, in a `0700 root:root` directory. It is refused outright — with the reason
  logged — when its owner, group or mode is wrong, when it is a symlink, or when any directory above
  it is group- or world-writable. `$WAZUH_CA_DIR` is held to the same directory rule.
* One `KEY=VALUE` per line. The file is **parsed, never sourced**: nothing in it is ever executed.
* The packages own a delimited block and nothing else. Lines you write outside it are never
  touched, reordered or reformatted, even when they carry the same key.
* Neither `/etc/wazuh` nor the file itself ships in any package.

```sh
# Written by the operator before installing
WAZUH_INDEXER_MANAGER_PASSWORD='Str0ng.Pass+01'

# >>> wazuh generated — do not edit <<<
# Editing a value here does not change the deployment.
# To rotate, use wazuh-passwords-tool.sh.
WAZUH_MANAGER_API_PASSWORD="zL9dH…"
WAZUH_MANAGER_WUI_PASSWORD="cF4nP…"
# >>> end wazuh generated <<<
```

> [!IMPORTANT]
> Editing a generated value here does not change the credential the manager already holds. Step 1
> of the order wins over the file, so the manager keeps what is in its own store and your edit has
> no effect. Use `wazuh-passwords-tool.sh` to rotate a credential in a running deployment.

### Reading a value back

Every value the packages write is **double-quoted**, with `\`, `"`, `$` and `` ` `` backslash-escaped
inside the quotes. A value you write yourself may be double-quoted, single-quoted or bare; all three
are read back identically, and the surrounding quotes are never part of the value.

This matters because the quotes are removed by the *parser*, not by the file format. Anything that
reads the file with `grep`/`cut`/`awk`, or hands it to a loader that does not unquote, gets the
quotation marks as part of the password and fails to authenticate with no visible cause:

```bash
# Wrong -- yields  "zL9dH…"  including the quotation marks
grep '^WAZUH_MANAGER_API_PASSWORD=' /etc/wazuh/credentials.env | cut -d= -f2-

# Right
sed -n "s/^WAZUH_MANAGER_API_PASSWORD=[\"']\{0,1\}\(.*[^\"']\)[\"']\{0,1\}$/\1/p" \
    /etc/wazuh/credentials.env
```

> [!WARNING]
> **Do not pass this file to `docker run --env-file` or `docker compose env_file`.** Docker does not
> strip quotation marks: it treats them as part of the value, so the container receives a password
> with literal `"` characters around it and every request it makes is rejected as `401`. Read the
> value out and pass it with `-e KEY=value` instead.

The file holds every plaintext password in the deployment, so delete it once every component is
installed and running — not earlier, because until then it is how the components hand credentials to
one another.

```bash
sudo rm /etc/wazuh/credentials.env
```

### Supplying a value through the environment

The same key names are read from the process environment, which overrides the file. On a package
install the value must be on the `sudo` command line: with `env_reset` active — the default on every
distribution Wazuh supports — an exported variable never reaches the maintainer script.

```bash
# Correct
sudo WAZUH_INDEXER_MANAGER_PASSWORD='Str0ng.Pass+01' apt-get install wazuh-manager

# Silently dropped: env_reset discards it
export WAZUH_INDEXER_MANAGER_PASSWORD='Str0ng.Pass+01'
sudo apt-get install wazuh-manager
```

That trap is why the file, not the command line, is the documented way to choose a value.

> [!IMPORTANT]
> Supplying `WAZUH_MANAGER_API_PASSWORD` or `WAZUH_MANAGER_WUI_PASSWORD` through the environment does
> **not** keep it off disk. The manager publishes every credential it owns into
> `/etc/wazuh/credentials.env` whether it generated the value or you supplied it, because the
> dashboard authenticates as `wazuh-wui` and reads the value from there — publishing only generated
> values would mean a deployment that chose its own passwords never hands them over. What protects
> it is the file: `0600 root:root` inside a `0700 root:root` directory, refused outright on every
> read and every write when the owner, the mode, a symlink or any ancestor is wrong. Only root can
> read it, and [deleting it](#the-credentials-file) once every component is running is the last step
> of an installation, not an optional one.
>
> `WAZUH_INDEXER_MANAGER_PASSWORD` is never published — the manager only consumes it.

## The password policy

Every password, supplied or generated, must be **12 to 64 characters from
`A-Z a-z 0-9 . , _ + : @ % ^ = ~ -` and contain at least one letter and one digit** — PCI DSS v4.0
requirement 8.3.6, applied identically by all three components. It is also the rule the Server API
enforces for `POST`/`PUT /security/users` and `rbac_control change-password`, so a value accepted
here is never one the API rejects later. A supplied value with any other character, including a
non-ASCII letter or a space, is invalid.

Generated passwords are 32 characters drawn from the same set, with a
lowercase letter, an uppercase letter and a digit guaranteed. Quotes, backslash, backtick, `$`, `!`
and `#` are left out deliberately, so a value is safe to paste through shell, YAML, JSON and
docker-compose interpolation without escaping.

> [!NOTE]
> The Server API rejects a password outside this rule with error `5009` (length) or `5007` (missing
> letter or digit).

This rule replaces an earlier one that also demanded an uppercase letter, a lowercase letter and a
symbol. It is a lower floor for an operator who chooses their own value, for three reasons:

* **It has to be one rule.** The resolver validates a value at installation and the Server API
  validates it again at rotation. Two different rules means a value the installation accepts and the
  API later refuses — a deployment that comes up and cannot be administered. PCI DSS 8.3.6 is the
  rule the indexer and the dashboard implement, so it is the one all three share.
* **Composition rules are not what makes a password strong.** NIST SP 800-63B §5.1.1.2 advises
  against them: they push operators toward predictable substitutions while barely enlarging the
  search space. The 12-character minimum — the control that does — is unchanged.
* **The weakness this release closes was not the shape of a chosen password.** It was that every
  installation shipped `wazuh`/`wazuh` and `wazuh-wui`/`wazuh-wui`. Where you supply nothing, a
  32-character value is generated instead, which no composition rule would improve on.

## Installing and starting

The installer creates what it can and has no opinion about whether the manager can run: it exits `0`
whatever it could not resolve, prints no warning, and neither enables nor starts the service. You
start it when you are ready:

```bash
sudo apt-get install wazuh-manager
sudo systemctl enable --now wazuh-manager
```

Install order does not matter. A manager installed before the indexer resolves nothing at install
time; by the time you start it the indexer has published its key, and it resolves.

## When the manager does not start

Service start runs the password and keystore order again — not merely a check — so the manager picks
up whatever became available since it was installed. When something is still missing it refuses to
start and names it. There is no repair command: fix the key and start the service again.

```
$ sudo systemctl enable --now wazuh-manager
Job for wazuh-manager.service failed.

$ systemctl status wazuh-manager
  resolve-credentials: MISSING WAZUH_INDEXER_MANAGER_PASSWORD
  resolve-credentials:         set it in /etc/wazuh/credentials.env, or install wazuh-indexer on this host first
```

1. Read the journal: `journalctl -u wazuh-manager -n 50`.
2. Set the missing key in `/etc/wazuh/credentials.env`.
3. `sudo systemctl start wazuh-manager`.

Validation covers **presence and format only**. The pre-start step never opens a network connection,
because making a service's start depend on reaching its peer would break boot ordering and cluster
restarts. A credential that is present but wrong still fails as a `401` at runtime.

No value is ever printed — not in the installer's output, not in the journal. An invalid value is
reported by the name of its key and the rule it failed.

## Certificates

The manager needs two TLS pairs, both leaves of the same CA:

| File | Used by |
|------|---------|
| `etc/certs/remoted.pem`, `remoted-key.pem` | the HTTPS agent listener on 1517, and `wazuh-manager-authd` on 1515 |
| `etc/certs/indexer-connector.pem`, `indexer-connector-key.pem` | the client certificate presented to the indexer |
| `etc/certs/root-ca.pem` | the trust anchor for both, served to agents on `GET /cacerts` |

### Issued at installation, and at no other moment

The pairs are issued by the install, and neither a service start nor a package upgrade issues,
re-anchors or even re-examines them. Two reasons, and both matter in a distributed deployment:

* **Issuing a certificate is a signature, not a lookup.** Re-deriving the chain at every start would
  mean the CA directory has to still be there, still hold the anchor this manager's material was
  issued from, and still match it byte for byte. A deployment running on its own PKI stages a pair
  and nothing else — it has no reason to keep a copy of its root CA on every manager forever, and no
  reason to accept a manager that refuses to boot because that copy drifted or was tidied away.
* **They are the credential you legitimately replace out of band.** A password lives in one place the
  resolver owns; a certificate is rotated by whatever issues the rest of your estate's certificates.

So `/etc/wazuh/ca` is a bootstrap handoff, not a standing dependency. **You can delete it** once the
pairs are in `etc/certs`, and a manager provisioned entirely from outside never needs one at all.

What certificates the manager will accept is decided where it always was, against the files as they
are at start — which is the only state that matters:

* `wazuh-manager-conf validate` checks that the agent-listener pair and the authd material **exist**.
  It runs as root, so it does not tell you whether the `wazuh-manager` user can read them.
* `remoted` probes its own pair with `access(R_OK)` **after** dropping privileges, and refuses to
  start the listener when it cannot read either file.
* The TLS handshake decides the rest.

> [!NOTE]
> The Indexer Connector pair is not covered by either check. `<indexer><ssl>` is deliberately left
> out of the configuration validator's file list, so that a manager with no indexer can still start,
> and nothing probes it after the privilege drop. A `indexer-connector-key.pem` that exists but is
> not readable by `wazuh-manager` therefore passes every check that runs as root and fails later,
> when the connector is loaded. The install checks the ownership and mode of both pairs, so a pair
> the manager issued is correct by construction — when you provision one by hand, get the ownership
> right from the table below.

### What the install does

Which flow applies is decided by what is in `$WAZUH_CA_DIR` (default `/etc/wazuh/ca`) — there is no
mode flag, because the presence of a private key beside the anchor is the signal:

| In the CA directory | Pair already in `etc/certs` | Result |
|---------------------|------------------------------|--------|
| nothing | no | mint a bootstrap CA, then issue both pairs from it |
| anchor + key | no | issue both pairs from the CA found |
| anchor + key | one of the two | keep that pair and issue only the missing one, if the kept pair was issued by that CA; **nothing issued** otherwise |
| nothing | one of the two | **nothing issued**: no CA is minted, since its anchor would not match the pair |
| anchor only | yes | use both, install the anchor if `etc/certs` lacks it, generate nothing |
| anchor only | no | install the anchor; **nothing issued** |

A pair already in `etc/certs` is never overwritten.

A CA you place yourself has to match what the resolver checks, or it is refused and nothing is
issued: the directory `root:root 0700`, `root-ca.pem` `root:root 0644` and `root-ca.key`
`root:root 0400`.

```bash
sudo install -d -m 0700 -o root -g root /etc/wazuh/ca
sudo install -m 0644 -o root -g root root-ca.pem /etc/wazuh/ca/root-ca.pem
sudo install -m 0400 -o root -g root root-ca.key /etc/wazuh/ca/root-ca.key
```

A host that was never given a CA private key cannot sign, and so cannot be where one leaks from.

When the install issues nothing it says so and still exits `0` — there is no such thing as a failed
install here. The manager then has no certificates, and refuses to start with the configuration
validator's verdict naming the file:

```
(1244): Invalid configuration at '/remote/https/certificate': file not found:
/var/wazuh-manager/etc/certs/remoted.pem (issued by the credential resolver at installation, or
provisioned externally, e.g. with wazuh-certs-tool)
```

Provision the pair and start the service again; nothing has to be reinstalled.

To supply a pre-issued pair, place it in `etc/certs` **before** installing, or afterwards — either
way it is used as it is and never replaced.

```bash
sudo install -d -m 1770 -o root -g wazuh-manager /var/wazuh-manager/etc/certs
sudo install -m 0640 -o root -g wazuh-manager root-ca.pem /var/wazuh-manager/etc/certs/root-ca.pem
sudo install -m 0640 -o wazuh-manager -g wazuh-manager node-1-remoted.pem \
    /var/wazuh-manager/etc/certs/remoted.pem
sudo install -m 0640 -o wazuh-manager -g wazuh-manager node-1-remoted-key.pem \
    /var/wazuh-manager/etc/certs/remoted-key.pem
sudo install -m 0640 -o root -g wazuh-manager node-1.pem \
    /var/wazuh-manager/etc/certs/indexer-connector.pem
sudo install -m 0640 -o root -g wazuh-manager node-1-key.pem \
    /var/wazuh-manager/etc/certs/indexer-connector-key.pem
```

The two pairs do not share an owner. `remoted.pem` and `remoted-key.pem` are opened by `remoted` and
`authd` **after** the privilege drop, so they belong to `wazuh-manager`; the indexer material is read
as root and stays root-owned, so a daemon cannot replace the manager's own trust anchor.

### Subject alternative names

The two leaves are configured independently, because they are presented to different peers:

| Setting | Configures | Discovery when unset |
|---------|------------|----------------------|
| `WAZUH_MANAGER_CERT_SANS` | `indexer-connector.pem` | hostname, FQDN, `localhost`, loopback, and the global addresses on default-route interfaces |
| `WAZUH_MANAGER_REMOTED_CERT_SANS` | `remoted.pem` | hostname, FQDN, `localhost`, loopback, and **every global-scope** address `ip -o addr show` reports — including addresses on interfaces that are not on the default route, that are virtual, or that are down |

Remoted's list is deliberately the wider of the two: agents reach the manager over whatever address
the operator pointed them at, which is frequently not the one on the default route, and a manager
issued a narrower certificate installs cleanly and then fails at the first peer connection.

It is wider by *interface*, not by *scope*. Link-local (`fe80::`) and host-scope addresses are left
out: no peer can match them, so they would be disclosure with no function — and a link-local address
formed the classic way carries the interface's MAC into a certificate that is served to every client
completing a handshake on port 1517. If a node must present an address discovery does not pick up,
set `WAZUH_MANAGER_REMOTED_CERT_SANS` explicitly; it replaces the whole list.

An explicit value **replaces** discovery for that leaf; it does not extend it. `localhost`,
`127.0.0.1` and `::1` are appended to it all the same. Wildcard DNS names,
scoped IPv6 and CIDR notation are refused — under a shared CA, a node holding a wildcard could
present a certificate for any other node — and equivalent textual IPv6 addresses are deduplicated.


```sh
WAZUH_MANAGER_CERT_SANS='DNS:wazuh.corp.local,IP:10.0.1.11'
WAZUH_MANAGER_REMOTED_CERT_SANS='DNS:agents.corp.local,IP:10.0.1.11,IP:2001:db8::10'
```

Changing either setting afterwards renews nothing: a complete existing pair always wins, and a start
issues nothing in any case. To reissue, remove the pair and run the resolver's `--install` mode
again:

```bash
sudo rm /var/wazuh-manager/etc/certs/remoted.pem /var/wazuh-manager/etc/certs/remoted-key.pem
sudo /var/wazuh-manager/bin/wazuh-manager-resolve-credentials --install
```

> [!WARNING]
> Discovery failing is an **error**, not a quiet fall back to loopback: a node issued a
> loopback-only certificate installs cleanly and then fails at the first peer connection, possibly
> weeks later, because the pre-start step opens no network connections. If `ip -o addr show` cannot
> run, supply the SANs explicitly. Check what a node actually presents with
> `openssl x509 -in /var/wazuh-manager/etc/certs/remoted.pem -noout -text`.

The bootstrap CA is local to the host and disposable. A host that minted its own and later joins a
real cluster does not merge trust: the cluster's CA re-issues everything.

## Container images

A container image built by installing the package is a special case worth stating plainly: the
package's `postinst` runs the resolver, so the image layer carries a seeded `rbac.db`, a bootstrap
CA **including its private key**, and an issued certificate set. Every container started from that
image would share all of it — which is worse than a shipped default password, because it looks
random.

Clear them so each container resolves from nothing. `--clear` and `--install` are a pair — the first
wipes, the second resolves — because certificates are only ever issued at install:

```dockerfile
# end of the Dockerfile: ship an image with no credentials at all
RUN /var/wazuh-manager/bin/wazuh-manager-resolve-credentials --clear
```

```bash
# entrypoint, before the first start: resolve this container's own. Idempotent, so a restarted
# container that already resolved is a no-op.
/var/wazuh-manager/bin/wazuh-manager-resolve-credentials --install
```

`--clear` removes `rbac.db`, the keystore, the certificates and the bootstrap CA, and takes the
manager's own keys out of the managed block of the credentials file.

An image that bakes in certificates of its own — issued for the service names its containers will
answer to — needs neither call for them: overwrite the files in `etc/certs` and nothing will ever
look at where they came from.

> [!WARNING]
> `--clear` is the one destructive operation here, and `rbac.db` holds **every** Server API user,
> role, policy and rule — not only the two default users. On a deployment with custom RBAC, clearing
> means recreating it. It refuses to run while the manager is running; stop the service first.

Two things it deliberately leaves alone: a CA directory holding only an anchor, since no private key
beside it means the CA was issued elsewhere and is not the manager's to destroy, and anything
outside the managed block or belonging to another component.

## Upgrades and removal

An upgrade takes step 1 for everything: existing values are detected and left untouched, and any key
still in the file is ignored whatever it contains. Replacing a credential on a running deployment is
rotation, not installation.

Certificates are not looked at at all. An upgrade never re-examines, re-anchors or reissues the pair
in `etc/certs`, so one you replaced with your own PKI's — and the absent CA directory that usually
goes with it — survives every upgrade untouched.

What removal does depends on which package manager, because they do not offer the same operations:

| Command | Effect on the credentials file |
|---------|-------------------------------|
| `apt remove wazuh-manager` | untouched |
| `apt purge wazuh-manager` | the manager's own keys are removed from the managed block |
| `rpm -e wazuh-manager` / `dnf remove` | the manager's own keys are removed from the managed block |

RPM has no operation that removes a package while keeping its configuration, so an erase is the
equivalent of a DEB purge and is treated as one. Both take exactly the same four keys
(`WAZUH_MANAGER_API_PASSWORD`, `WAZUH_MANAGER_WUI_PASSWORD`, `WAZUH_MANAGER_CERT_SANS`,
`WAZUH_MANAGER_REMOTED_CERT_SANS`) and only from inside the managed block — lines you wrote are never
touched, even when they carry the same key.

The last component out then removes what is left, `/etc/wazuh` included. "Last" is asked of the
package manager: the file, the CA directory and `/etc/wazuh` go only when neither `wazuh-indexer`
nor `wazuh-dashboard` is still installed, so purging the manager on a host that also runs one of
them cannot take the trust material out from under it. A CA relocated with `WAZUH_CA_DIR` is left
alone, and `/etc/wazuh` is removed with `rmdir`, so anything of yours in it survives.

## Rotation

Use `wazuh-passwords-tool.sh` for a coordinated change on a running deployment. A package must never
reconfigure a sibling — it is invoked by the package manager as a side effect of an unrelated action
— whereas the tool is invoked by you, at a moment of your choosing.

No rotation path updates `/etc/wazuh/credentials.env`, so a value left there after a change is stale.

To change a Server API password on its own:

```bash
sudo /var/wazuh-manager/bin/rbac_control change-password
```
