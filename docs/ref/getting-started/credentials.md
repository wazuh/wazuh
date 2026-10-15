# Credentials

The manager sets up every credential it owns or consumes with one program,
`/var/wazuh-manager/bin/wazuh-manager-resolve-credentials` (the *credential resolver*). It runs:

- when the package is installed or upgraded, and from `install.sh`;
- before every start, from `wazuh-manager-control`: a read-only check first, then a step that completes what is
  missing.

The resolver is a Python program run by the manager's bundled interpreter. It calls no tool from the host and
keeps everything under the manager's configuration directory, `/etc/wazuh-manager` (written `<CONF>` below):
nothing goes to `/etc/wazuh`.

What it handles:

| Credential | Owned by the manager | Where it ends up |
|------------|----------------------|------------------|
| Server API passwords of `wazuh` and `wazuh-internal-client` | yes: supplied or generated | seeded into `rbac.db`, published in `<CONF>/export/credentials.env` |
| Indexer password (`wazuh-manager` user on the indexer) | no: supplied or read from the indexer | the manager's keystore |
| The manager's CA | yes: minted at installation, or staged by you | `<CONF>/ca/`, published in `<CONF>/export/ca.pem` |
| Agent listener and Server API pairs | yes: issued at installation, or staged by you | `<CONF>/certs/remoted.pem`, `apid.pem` |
| Indexer CA and client pair | no: imported from the indexer, or staged by you | `<CONF>/certs/indexer-ca.pem`, `indexer-connector.pem` |

## Files and modes

Everything the resolver reads or writes, with the owner and mode it requires. It never repairs an owner or a
mode: an entry that does not match is refused (see [File safety](#file-safety)).

| Path | Owner, mode | Written by | Content |
|------|-------------|------------|---------|
| `<CONF>/` | `root:wazuh-manager 0770` (the group needs `rwx`; `1770` is accepted) | installer | the configuration directory |
| `<CONF>/local.env` | `root`, not group- or world-writable (use `0600 root:root`) | you | values you supply ([The keys](#the-keys)) |
| `<CONF>/ca/` | `root:root 0700` | resolver | the manager's CA |
| `<CONF>/ca/root-ca.pem` | `root:root 0644` | resolver or you | the CA certificate |
| `<CONF>/ca/root-ca.key` | `root:root 0400` | resolver or you | its private key; absent when you stage the certificate alone |
| `<CONF>/ca/.wazuh-manager-bootstrap-ca` | `root:root 0600` | resolver | marker: this host minted the CA |
| `<CONF>/export/` | `root:root 0700` | resolver | what the manager publishes for the dashboard on the same host |
| `<CONF>/export/credentials.env` | `root:root 0600` | resolver | the two Server API passwords |
| `<CONF>/export/ca.pem` | `root:root 0644` | resolver | copy of `ca/root-ca.pem`: what clients verify the Server API with |
| `<CONF>/certs/` | `root:wazuh-manager 0750`, exactly | installer | TLS material the daemons read |
| `<CONF>/certs/root-ca.pem` | `root:wazuh-manager 0640` | resolver (only when absent) | the agents' CA bundle, served by remoted |
| `<CONF>/certs/remoted.pem`, `remoted-key.pem` | `root:wazuh-manager 0640` | resolver or you | agent listener pair |
| `<CONF>/certs/apid.pem`, `apid-key.pem` | `root:wazuh-manager 0640` | resolver or you | Server API pair |
| `<CONF>/certs/indexer-ca.pem` | `root:wazuh-manager 0640` | resolver (import) or you | the CA the indexer connector trusts |
| `<CONF>/certs/indexer-connector.pem`, `indexer-connector-key.pem` | `root:wazuh-manager 0640` | resolver (import) or you | client pair the manager presents to the indexer |
| `<CONF>/certs/.indexer-ca.imported`, `.indexer-connector.imported` | `root:wazuh-manager 0640` | resolver | markers: these files were imported, not staged |
| `/etc/wazuh-indexer/export/` | `root`, any group, not group- or world-writable | `wazuh-indexer` | read only: `credentials.env`, `ca.pem`, `manager-client.pem`, `manager-client-key.pem` |
| `/var/wazuh-manager/api/configuration/security/rbac.db` | | resolver (through `rbac_control.py`) | Server API users, roles and policies |
| `/var/wazuh-manager/queue/keystore/` | | resolver (through `wazuh-manager-keystore`) | the indexer username and password |

The service account `wazuh-manager` can read the files in `certs/` through its group, and nothing else on the
list: `ca/`, `export/` and `local.env` are root's.

## The keys

| Key | Purpose | When unset |
|-----|---------|------------|
| `WAZUH_MANAGER_API_PASSWORD` | password of the Server API user `wazuh` | generated |
| `WAZUH_MANAGER_WUI_PASSWORD` | password of `wazuh-internal-client`, the user the dashboard authenticates as | generated |
| `WAZUH_INDEXER_MANAGER_PASSWORD` | password of the `wazuh-manager` user on the indexer | read from the indexer's `/etc/wazuh-indexer/export/credentials.env` when the indexer runs on this host; otherwise the start refuses (`MISSING`) |
| `WAZUH_MANAGER_NODE_NAME` | common name of the CA and the pairs, first DNS name of both pairs; a DNS name of at most 64 characters (the limit of a certificate's common name: a longer one is `INVALID` and no pair is issued) | the host name up to its first dot |
| `WAZUH_MANAGER_REMOTED_CERT_SANS` | subject alternative names of the agent listener pair | discovered ([Subject alternative names](#subject-alternative-names)) |
| `WAZUH_MANAGER_APID_CERT_SANS` | subject alternative names of the Server API pair; never inherits remoted's list | discovered |

`WAZUH_MANAGER_CERT_SANS` is gone: it named the indexer client pair, which now comes from the indexer. When it is
set, the resolver prints `WARNING: WAZUH_MANAGER_CERT_SANS is ignored` and goes on.

Each key is looked up in order, and the first value found wins:

1. the process environment;
2. `<CONF>/local.env`;
3. for `WAZUH_INDEXER_MANAGER_PASSWORD` only, the indexer's `/etc/wazuh-indexer/export/credentials.env`.

An empty value counts as unset for a password. A value that breaks a rule is reported (`INVALID`) and **never
replaced by a generated one**: the start refuses until you fix it. A `local.env` that is unsafe or malformed is
rejected as a whole, and then nothing is generated or seeded from defaults in that run either.

`local.env` holds `NAME=value` lines. Surrounding whitespace is trimmed, blank lines and `#` comments are skipped,
and one pair of matching single or double quotes around the value is removed. Nothing is expanded or unescaped. A
name given twice, an unbalanced quote or any other line is an error naming the file and the line.

```bash
sudo install -m 0600 -o root -g root /dev/null /etc/wazuh-manager/local.env
sudo tee /etc/wazuh-manager/local.env > /dev/null <<'EOF'
WAZUH_INDEXER_MANAGER_PASSWORD='<the wazuh-manager password on the indexer>'
WAZUH_MANAGER_API_PASSWORD='<your value>'
EOF
```

### Supplying a value through the environment

On a package install the variable must be on the `sudo` command line. With `env_reset` active (the default on
every distribution Wazuh supports), an exported variable never reaches the maintainer script:

```bash
# Correct
sudo WAZUH_INDEXER_MANAGER_PASSWORD='Str0ng.Pass+01' apt-get install wazuh-manager

# Silently dropped: env_reset discards it
export WAZUH_INDEXER_MANAGER_PASSWORD='Str0ng.Pass+01'
sudo apt-get install wazuh-manager
```

systemd starts the manager from a clean environment, so a value needed at start belongs in `local.env`.

## The password policy

A supplied password must be 12 to 64 characters long, use only `A-Z a-z 0-9` and `. , _ + : @ % ^ = ~ -`, and
contain a lowercase letter, an uppercase letter, a digit and one of those symbols. A generated one is 32
characters drawn the same way.

The Server API's own rule, applied when a password is changed later, is wider: 12 to 64 printable ASCII characters
with a letter and a digit. Every value the resolver accepts or generates also passes it, and the resolver's tests
check that against the Server API's code. The reverse is not guaranteed: a password chosen through the Server API
may be one the resolver refuses.

## The published passwords

The Server API passwords are seeded into `rbac.db` and published, generated or supplied, in
`<CONF>/export/credentials.env`. The dashboard on the same host authenticates as `wazuh-internal-client` with the
value it reads there. Only root can read the file:

```text
# Published by wazuh-manager. Read by the dashboard on this host. Do not edit.
WAZUH_MANAGER_API_PASSWORD=<32 characters>
WAZUH_MANAGER_WUI_PASSWORD=<32 characters>
```

To read a value, parse the line; never `source` the file:

```bash
sudo sed -n 's/^WAZUH_MANAGER_API_PASSWORD=//p' /etc/wazuh-manager/export/credentials.env
```

Seeding happens once: an existing, non-empty `rbac.db` is never reseeded, whatever the keys say. A worker node
seeds nothing ([Cluster deployments](#cluster-deployments)). `WAZUH_INDEXER_MANAGER_PASSWORD` is never published:
the manager only consumes it.

## What the dashboard takes from the manager

The dashboard calls the Server API over TLS and logs in as `wazuh-internal-client`. It needs two things from the
manager, both in `<CONF>/export/`:

| File | What it is | Used for |
|------|------------|----------|
| `export/ca.pem` (`root:root 0644`) | the manager CA's **certificate**, its public part only | verifying the certificate `wazuh-manager-apid` presents (`certs/apid.pem`) |
| `export/credentials.env` (`root:root 0600`), key `WAZUH_MANAGER_WUI_PASSWORD` | the `wazuh-internal-client` password | logging in to the Server API |

No key is published. `ca/root-ca.key` stays in `ca/` (`root:root 0400`) and is never copied to the dashboard: the
certificate alone is enough to verify the API.

**Dashboard on the same host.** It reads both files as root; nothing has to be copied.

**Dashboard on another host.** Copy the certificate to it, and put the password in the dashboard's
`wazuh_core.hosts.<host>.password`. In a 5.0 package installation the dashboard verifies the Server API with
`/etc/wazuh-dashboard/certs/manager-ca.pem`:

```bash
# on the manager
sudo cat /etc/wazuh-manager/export/ca.pem > manager-ca.pem
# on the dashboard host
sudo install -o root -g wazuh-dashboard -m 640 manager-ca.pem /etc/wazuh-dashboard/certs/manager-ca.pem
```

The name the dashboard uses to reach the manager must be one of the names in `apid.pem`, which the resolver takes
from `WAZUH_MANAGER_APID_CERT_SANS` or discovers ([Subject alternative names](#subject-alternative-names)).

**Check it** on the dashboard host, with `<manager>` being that name:

```bash
# the same certificate on both sides
openssl x509 -noout -subject -fingerprint -sha256 -in /etc/wazuh-dashboard/certs/manager-ca.pem
# the Server API's certificate verifies against it, for that name
openssl s_client -connect <manager>:55000 -CAfile /etc/wazuh-dashboard/certs/manager-ca.pem \
    -verify_hostname <manager> -verify_return_error </dev/null 2>&1 | grep 'Verify return code'
# and the password logs in (curl prompts for it, so it does not reach the process list)
curl --cacert /etc/wazuh-dashboard/certs/manager-ca.pem -u wazuh-internal-client \
    -X POST "https://<manager>:55000/security/user/authenticate"
```

The fingerprint must match `openssl x509 -noout -fingerprint -sha256 -in /etc/wazuh-manager/export/ca.pem` on the
manager, the verification must end in `Verify return code: 0 (ok)`, and the login must return a token.

**When it changes.** `export/ca.pem` changes only when the manager's CA does: a CA staged again or rotated. The
next start publishes the new one ([Rotation](#rotation)). Copy it again to every dashboard on another
host; until then their verification of the Server API fails. A new `wazuh-internal-client` password works the
same way ([Rotation](#rotation)).

## The resolver and its modes

```text
wazuh-manager-resolve-credentials [--install|--upgrade|--prestart|--check|--clear] [-q] [-H <home>]
```

| Mode | Called by | Does | Exit |
|------|-----------|------|------|
| `--install` | DEB `postinst` and RPM `%post` on a fresh install, `install.sh` | seeds the passwords, stores the indexer password, mints the CA when nothing is there, issues the two server pairs, imports the indexer trust | always `0` |
| `--upgrade` | DEB `postinst` and RPM `%post` on an upgrade | completes passwords, keystore and indexer trust; publishes the CA in `export/ca.pem` again when the copy there differs; validates the CA and the pairs, never mints or issues | always `0` |
| `--prestart` (default) | `wazuh-manager-control` before the daemons start, on `start`, `restart` and `reload` | every `--check` test, then what `--upgrade` does; refuses the start when anything is missing, invalid or unsafe | `0` or `1` |
| `--check` | `wazuh-manager-control` first thing on `start`, `restart` and `reload` | read-only: no lock, nothing written, and no subprocess but `wazuh-manager-conf --skip-file-checks dump`, which reads the [configured file names](#configured-file-names); reports `UNSAFE` and `INVALID`, never `MISSING` | `0` or `1` |
| `--clear` | you | removes what the resolver made ([Container images](#container-images)) | `0` or `1` |

`-q` prints only problems. `-H` names a non-default installation directory; the configuration directory is
always `/etc/wazuh-manager`. Exit `2` means a usage error, a caller that is not root, another run holding the lock
on `<CONF>/ca` for 60 seconds, or an internal error.

The installer never fails the package transaction: what it cannot resolve at install time may be in place by the
time you start the service, so the start is where the verdict counts. A DEB reinstall from the config-files state
(after `apt remove`) runs as an install when `certs/remoted.pem` is missing.

A fresh install with no indexer on the host:

```text
resolve-credentials: WAZUH_MANAGER_API_PASSWORD: generated
resolve-credentials: WAZUH_MANAGER_WUI_PASSWORD: generated
resolve-credentials: seeded /var/wazuh-manager/api/configuration/security/rbac.db; the passwords are in /etc/wazuh-manager/export/credentials.env
resolve-credentials: CA CN=wazuh-manager-node1,OU=Wazuh,O=Wazuh,L=California,C=US: minted
resolve-credentials: wrote /etc/wazuh-manager/certs/root-ca.pem (the manager's CA)
resolve-credentials: /etc/wazuh-manager/certs/remoted.pem: issued; DN CN=node1,OU=Wazuh,O=Wazuh,L=California,C=US; SANs DNS:node1, IP:192.0.2.10, DNS:localhost, IP:127.0.0.1, IP:::1
resolve-credentials: /etc/wazuh-manager/certs/apid.pem: issued; DN CN=node1,OU=Wazuh,O=Wazuh,L=California,C=US; SANs DNS:node1, IP:192.0.2.10, DNS:localhost, IP:127.0.0.1, IP:::1
MISSING WAZUH_INDEXER_MANAGER_PASSWORD: set it in /etc/wazuh-manager/local.env (copy it from the indexer's /etc/wazuh-indexer/export/credentials.env), or install wazuh-indexer on this host first
MISSING /etc/wazuh-manager/certs/indexer-ca.pem: install wazuh-indexer on this host first, or stage the indexer's export/ca.pem there
MISSING /etc/wazuh-manager/certs/indexer-connector.pem: install wazuh-indexer on this host first, or stage a pair issued by the indexer's CA for this node
```

## When the manager does not start

Every problem is one line on standard error, printed once, in the form `KIND <path or key>: <reason>`. No line
ever carries a secret.

| Kind | Meaning | Examples |
|------|---------|----------|
| `MISSING` | something a start needs is absent; `--prestart` refuses, `--check` never says it | `MISSING WAZUH_INDEXER_MANAGER_PASSWORD: set it in /etc/wazuh-manager/local.env …` |
| `INVALID` | something in place is wrong | `INVALID /etc/wazuh-manager/local.env:2: not a NAME=value line` · `INVALID WAZUH_INDEXER_MANAGER_PASSWORD: must be 12 to 64 characters (set in /etc/wazuh-manager/local.env:1)` · `INVALID /etc/wazuh-manager/certs/remoted.pem: expired` |
| `UNSAFE` | an entry root may not trust: wrong owner or mode, a link, a directory where a file belongs | `UNSAFE /etc/wazuh-manager/local.env: group-writable` |
| `WARNING` | indexer material that only the clock refuses: the indexer CA, a listed CA file, the client pair or a CA on its path is expired or not valid yet, and nothing else is wrong with it. It **does not** refuse the start; the indexer connection fails until the material is renewed or the clock is right | `resolve-credentials: WARNING: /etc/wazuh-manager/certs/indexer-connector.pem: expired on 2026-10-14 20:03:45 UTC; the indexer connection fails until it is renewed or the clock is right` |

`wazuh-manager-control` relays those lines to standard error and to `logs/wazuh-manager.log`, starts nothing, and
says why:

| When | stdout | With `-j` | Log line |
|------|--------|-----------|----------|
| `--check` reports `UNSAFE` | `Unsafe credentials. Exiting` | `{"error":22,"message":"Unsafe credentials."}` | `wazuh-manager-control: ERROR: unsafe credentials` |
| `--check` reports `INVALID` | `Invalid credentials. Exiting` | `{"error":22,"message":"Invalid credentials."}` | `wazuh-manager-control: ERROR: invalid credentials` |
| the check itself cannot run | `Cannot check the credentials. Exiting` | `{"error":22,"message":"Cannot check the credentials."}` | `wazuh-manager-control: ERROR: cannot check the credentials` |
| `--prestart` fails | `Unresolved credentials. Exiting` | `{"error":21,"message":"Unresolved credentials."}` | `wazuh-manager-control: ERROR: unresolved credentials` |

`--check` runs before the configuration is validated, and on `restart` before anything is stopped. A refused
`restart` therefore leaves the running daemons as they are.

A `WARNING` refuses nothing: the start goes on, and each warning is also written to `logs/wazuh-manager.log` as
`wazuh-manager-control: WARNING: <path>: …`. Only the indexer material's validity window is treated this way.
Anything else wrong with it (a key that does not match, the wrong issuer, no `clientAuth`, not a CA, missing files,
an unsafe export), and an expired or not-yet-valid server pair, bundle or manager CA, still refuses the whole start.
`--check` with only warnings ends with `check: no problem found (<n> warnings)`.

Run the check yourself to see the full list:

```bash
sudo /var/wazuh-manager/bin/wazuh-manager-resolve-credentials --check
```

## File safety

`<CONF>` is writable by the service group, because `authd`, `remoted` and the Server API write there. So the
resolver trusts nothing in it by name:

- every entry is opened from its parent directory without following a link, and checked on the opened file;
- a file it reads must be root's, not group- or world-writable, with a single link;
- `ca/` and `export/` must be root's `0700` directories, and `certs/` root's, group `wazuh-manager`, mode exactly
  `0750`: the daemons open its files by name through that group, which never writes there;
- `<CONF>` itself must leave its group `rwx`: the daemons write there and cross it to reach `certs/`. A mode that
  locks them out (`0750`, `0700`) is refused as `UNSAFE /etc/wazuh-manager: mode is 0750, missing 0020`, so the start stops on
  the resolver's line instead of on a daemon that cannot read its certificate;
- anything in `certs/` that root does not own is refused: only root can write there, so such an entry was
  planted;
- `ca/` and `export/` have the same owner and mode, so they are told apart by what they hold. Either one holding
  the other's files is refused as a swap.

An `export/ca.pem` that differs from `ca/root-ca.pem` is not an attack: it means the CA was staged again by hand.
`--check` lets the start go on and says so (`… differs from …; --prestart publishes it again`), and `--prestart`
publishes it again (`published /etc/wazuh-manager/export/ca.pem again: it differed from …`).

A writing run that finds anything unsafe stops before it writes. It re-checks the directories it is about to
write through on the very handles it writes with, so renaming entries in `<CONF>` mid-run redirects nothing.

What the service account can still do, because `<CONF>` has no sticky bit: rename or hide `local.env` or `ca/`.
The resolver then refuses (`UNSAFE`), or carries on as if you had supplied nothing (generated passwords,
discovered names). It never uses anything the account wrote, and never discloses a secret to it.

## Certificates

The manager uses two server pairs of its own, both issued by its CA (directly or through intermediate CAs), plus the
indexer's CA and a client pair the indexer issued for it:

| File | Role | Comes from |
|------|------|------------|
| `certs/remoted.pem` | the agent listener (remoted's HTTPS, `authd`) | the manager's CA |
| `certs/apid.pem` | the Server API | the manager's CA |
| `certs/root-ca.pem` | the bundle agents and remoted trust; may hold rotation CAs | the manager's CA, written once |
| `certs/indexer-ca.pem` | what the indexer connector trusts | the indexer |
| `certs/indexer-connector.pem` | what the manager presents to the indexer | the indexer |

### The manager's CA

| `<CONF>/ca/` holds | `--install` | `--upgrade` and `--prestart` |
|--------------------|-------------|------------------------------|
| nothing, and `certs/` holds no pair and no `root-ca.pem` | mints a CA (RSA 2048, SHA-256, ten years, `CN=wazuh-manager-<node>`) and the marker | `MISSING …/ca/root-ca.pem` |
| nothing, but pairs or `root-ca.pem` are already in `certs/` | `MISSING …/ca/root-ca.pem: stage the CA that issued the pairs` (never a second CA beside existing material) | same |
| `root-ca.pem` and `root-ca.key` | validated and used to issue what is missing | validated |
| `root-ca.pem` alone | validated; nothing can be issued here, the pairs must be staged | validated |
| `root-ca.key` alone | `INVALID …/ca/root-ca.key: no certificate beside it` | same |

The CA must be a single self-signed certificate with `CA:TRUE`, inside its validity window, with an unencrypted
key that matches it. An intermediate CA is not accepted here: it belongs in the pair files, after the leaf (see
[Server pairs](#server-pairs)). Every writing mode publishes it in `export/ca.pem` when the copy there is absent or
differs, and `--install` writes `certs/root-ca.pem` only when that file is absent. An existing bundle must contain
the CA. Its bytes are never rewritten, so rotation CAs and the publication block `wazuh-manager-certs` adds survive.

### Server pairs

A pair is issued at **installation only**, when it is absent and the CA has its key. The profile is RSA 2048,
SHA-256, ten years backdated one day, `CA:FALSE`, `serverAuth`, `CN=<node>` and the pair's own SAN list. The
certificate file carries the leaf followed by the CA.

At every other moment a pair is only checked:

- it must parse, match its key, be inside its window, be `CA:FALSE`, carry `serverAuth` if it has an
  `extendedKeyUsage`, and have subject alternative names;
- `apid.pem` must chain to `ca/root-ca.pem`. When an intermediate CA issued the leaf, the file carries the leaf
  first and then the intermediates, in order; they are used to build the path and are never trusted on their own;
- `remoted.pem` must chain to a certificate of `certs/root-ca.pem` **on its own**: agents receive that file alone
  (`GET /cacerts`), so an intermediate CA that issued the remoted leaf goes in `certs/root-ca.pem`, where it is
  trusted as it is. The intermediates in `remoted.pem` are still sent in the handshake but do not count here;
- every CA on that path, the root included, must be valid now, `CA:TRUE`, allowed to sign certificates
  (`keyCertSign`, when it has a `keyUsage`) and, when it restricts its `extendedKeyUsage`, allowed `serverAuth`
  (`anyExtendedKeyUsage` alone is not enough, as for OpenSSL, which agents and the dashboard use). A pair signed only
  by an expired rotation CA kept in the bundle is refused, and so is one under a CA limited to `clientAuth`
  (`issuer CA: its extendedKeyUsage does not include serverAuth`).

A pair that does not chain is reported as `not issued by the manager's CA`, followed by the reason in brackets, for
example `(no path to it from the certificates in the file)` when an intermediate is missing from `apid.pem`, or
`(agents are handed /etc/wazuh-manager/certs/root-ca.pem alone: an intermediate CA that issued it belongs in that
file)` for remoted. remoted, `authd` and the
Server API send the whole file, so clients that trust the root verify the chain.

A broken pair, or half of one, is reported and never repaired or reissued. To replace a pair, put the new files in
place (`root:wazuh-manager 0640`); to have the resolver issue a new one, remove both files and run `--install`.

### Configured file names

The resolver checks the files the daemons are configured to serve, under whatever name the configuration gives:

| Options | Set in | Default | A relative path resolves against |
|---------|--------|---------|----------------------------------|
| `remote.https.certificate`, `remote.https.key` (agent listener) | `/etc/wazuh-manager/wazuh-manager.conf` | `certs/remoted.pem`, `certs/remoted-key.pem` | `/var/wazuh-manager` |
| `auth.ssl_manager_cert`, `auth.ssl_manager_key` (enrollment) | `/etc/wazuh-manager/wazuh-manager.conf` | the agent listener's pair | `/var/wazuh-manager` |
| `remote.https.ca_certificate` (the agents' bundle, `GET /cacerts`) | `/etc/wazuh-manager/wazuh-manager.conf` | `certs/root-ca.pem` | `/var/wazuh-manager` |
| `https.cert`, `https.key` (Server API) | `/var/wazuh-manager/api/configuration/api.yaml` | `apid.pem`, `apid-key.pem` | `/etc/wazuh-manager/certs` |
| `indexer.ssl.certificate_authorities` (the indexer's CAs) | `/etc/wazuh-manager/wazuh-manager.conf` | `certs/indexer-ca.pem` in the generated configuration | `/var/wazuh-manager` |
| `indexer.ssl.certificate`, `indexer.ssl.key` (the client pair) | `/etc/wazuh-manager/wazuh-manager.conf` | `certs/indexer-connector.pem`, `certs/indexer-connector-key.pem` in the generated configuration | `/var/wazuh-manager` |

- **Only directly in `/etc/wazuh-manager/certs`.** The service account can edit both configuration files, so a name
  anywhere else, or one with a `.` or `..` component, is refused and never opened:
  `INVALID remote.https.certificate: /etc/ssl/listener.pem is outside /etc/wazuh-manager/certs, the only place the resolver checks (set in /etc/wazuh-manager/wazuh-manager.conf)`.
- **The same checks** as for the default names: owner and mode (`root:wazuh-manager 0640`) and content. authd's
  pair, like remoted's, must chain to the agents' bundle on its own.
- **Only the default names are issued.** A pair under another name is yours to stage; at `--prestart` an absent one is
  `MISSING /etc/wazuh-manager/certs/listener.pem: configured as remote.https.certificate in /etc/wazuh-manager/wazuh-manager.conf; stage the pair (the resolver issues only remoted.pem, remoted-key.pem, apid.pem, apid-key.pem)`.
  While authd keeps the default names, `remoted.pem` is still issued for it. A bundle under another name is
  never created either (`… stage the agents' CA bundle there`).
- **A turned-off listener** (`auth.disabled` set to `yes`, `https.enabled: false` in `api.yaml`) has its pair
  neither checked nor reported missing. `--install` still issues the default pairs whose names are configured.
- **Reading the configuration.** Every mode, `--check` included, reads `wazuh-manager.conf` through
  `wazuh-manager-conf --skip-file-checks dump` and parses `api.yaml`; an absent `api.yaml`, or an option it does
  not set, means the Server API's default. When either cannot be read, the default names are checked and the start
  is refused: `INVALID /etc/wazuh-manager/wazuh-manager.conf: cannot read the TLS paths (wazuh-manager-conf exited with 1); run wazuh-manager-conf validate`,
  `INVALID /var/wazuh-manager/api/configuration/api.yaml: not valid YAML (line 3)`. An `api.yaml` replaced by a
  symbolic link is `UNSAFE`.

For the indexer connection:

- **Only the default names are imported.** `indexer-ca.pem` is imported from the indexer's export only while
  `certificate_authorities` lists it, and the client pair only while `certificate` and `key` name
  `indexer-connector.pem` and `indexer-connector-key.pem` ([Indexer trust](#indexer-trust)). Any other listed or
  configured file is yours to stage: checked, never written, and at `--prestart` an absent one is
  `MISSING /etc/wazuh-manager/certs/manager-client.pem: configured as indexer.ssl.certificate in /etc/wazuh-manager/wazuh-manager.conf; stage a pair issued by the indexer's CA for this node (the resolver imports only indexer-connector.pem and indexer-connector-key.pem)`
  or `MISSING …: configured in indexer.ssl.certificate_authorities in …; stage the indexer's CA there`.
- **Every listed CA file counts.** The connector merges them, so the client pair may chain to any of them, and each
  must hold only CA certificates.
- **An empty CA list** makes the connector verify the indexer against the system's trust store: no CA file is
  wanted, and the client pair gets the leaf checks only (key, validity, not a CA, `clientAuth`), with no chain test.
- **No client pair** (`certificate` and `key` both empty) means none is wanted or imported. One set without the other
  is refused: `INVALID indexer.ssl.key: must be set together with indexer.ssl.certificate (set in /etc/wazuh-manager/wazuh-manager.conf)`.
- A configuration with no `<ssl>` block takes the schema's defaults, an empty CA list and no client pair, so nothing
  is imported or required; the generated configuration always has the block.

### Subject alternative names

Each pair has its own list: `WAZUH_MANAGER_REMOTED_CERT_SANS` and `WAZUH_MANAGER_APID_CERT_SANS`. The Server API
list never inherits remoted's. A list holds comma-separated entries: `DNS:name`, `IP:address`, or a bare value
(an address when it has a colon or only digits and dots, a name otherwise). Zone ids, prefixes and wildcards are
refused, and an invalid list stops the issuance of both pairs before any is written. `localhost`, `127.0.0.1` and
`::1` are always appended.

When a list is unset, the names are discovered:

1. the node name, then the fully qualified name when it differs;
2. the addresses of the interfaces that carry a default route: the primary IPv4 address of each (private networks
   included, loopback and link-local left out) and their global IPv6 addresses (deprecated or tentative ones left
   out);
3. the loopback names.

Secondary IPv4 addresses are not discovered: name them in the list. With no address found, the pairs name the
node and loopback only, and the resolver warns which variable to set.

### Indexer trust

The indexer CA and the client pair under their default names follow one rule, decided by a marker file in `certs/`
(files under [configured names](#configured-file-names) are always staged):

| State in `certs/` | What happens |
|-------------------|--------------|
| absent | imported from `/etc/wazuh-indexer/export/` (`ca.pem`, `manager-client.pem`, `manager-client-key.pem`) when the indexer is on this host, the marker written first; otherwise `MISSING` |
| present with its marker (imported) | imported again when the indexer's files change; kept when they do not, or when the export is gone |
| present without a marker (staged by you) | validated, never replaced |
| one file of the pair only | `INVALID … half a pair` |

The CA file must hold CA certificates inside their validity window; an intermediate CA kept there is trusted as it
is. The client pair must chain to one of them, directly or through intermediate CAs that follow the leaf in
`indexer-connector.pem`. Every CA on the path must be valid now, allowed to sign and, when it restricts its
`extendedKeyUsage`, allowed `clientAuth`. The leaf must be inside its window, not be a CA, match its key, and carry
an `extendedKeyUsage` with `clientAuth`. A pair without it is refused.

The CA and the pair are taken from the export together or not at all: the pair that will be in place must chain
to the CA that will be in place. An export whose new CA comes with a pair that is refused, or that does not issue the
pair already in place, changes nothing, and is reported against the export:

```text
INVALID /etc/wazuh-indexer/export/manager-client.pem: its key does not match it
INVALID /etc/wazuh-indexer/export/ca.pem: does not issue the staged /etc/wazuh-manager/certs/indexer-connector.pem; nothing was imported
```

`--check` reports the same refusal, so a `restart` is refused before anything is stopped and the manager keeps
running on the material in place. When no pair is in place at all, the CA is imported alone and the pair stays `MISSING`.

A CA or client pair that only the clock refuses (expired, not valid yet) is a `WARNING`, never a refusal: in place,
it is kept; in the export, it is imported only when nothing usable is in place (a first import, or material that is
itself refused), never over a pair valid now. A node that boots with its clock behind therefore starts, and its
indexer connection works once the clock is right. The connector still validates TLS itself, so such material is
not used until it is valid.

An export that holds any file root may not trust is refused as a whole: nothing is imported from it in that run.
An import interrupted halfway, with the marker written but not every file, is recognised: `--check` lets the start
through, and the `--prestart` that follows finishes it.

`<indexer><ssl><certificate_authorities><ca>` in the generated configuration names
`/etc/wazuh-manager/certs/indexer-ca.pem`.

### Using certificates issued elsewhere

To run the manager on your own PKI, stage the files before installing, or before the next start:

1. the CA certificate in `<CONF>/ca/root-ca.pem` (`root:root 0644` in a `root:root 0700` directory), with its key
   `root-ca.key` (`0400`) only if this host should issue pairs;
2. the server pairs and `certs/root-ca.pem` in `<CONF>/certs/` (`root:wazuh-manager 0640`). When your PKI issued
   them from an intermediate CA, `apid.pem` carries the leaf followed by the intermediates, the intermediate that
   issued the remoted leaf is added to `certs/root-ca.pem`, and `ca/root-ca.pem` stays the root;
3. for an indexer on another host, its CA as `certs/indexer-ca.pem` and a client pair it issued for this node
   (with `clientAuth`) as `certs/indexer-connector.pem` and `indexer-connector-key.pem`, and the indexer password
   in `local.env`.

Staged files carry no marker, so the resolver validates them and never replaces them. If a CA was already minted
here, replace `ca/root-ca.pem` and remove `ca/root-ca.key` and `ca/.wazuh-manager-bootstrap-ca`; the next start
publishes the new CA in `export/ca.pem`.

## Cluster deployments

Every node resolves credentials for itself. The cluster synchronizes `client.keys`, `authd.pass`,
`enrollment_tokens.json`, `shared/` and `var/multigroups/`, and none of `ca/`, `export/`, `local.env` or `certs/`.

- **Stage the same CA on every node before installing**, in `<CONF>/ca/` (`root-ca.pem`, and `root-ca.key` where
  pairs are issued). A node that mints its own CA trusts only itself, and an agent that reaches another node will
  not trust what it presents. Each node presents its own listener pair, which must name the addresses agents use
  to reach that node (behind a load balancer, the balancer's name as well).
- **Back up each node's credentials with it.** The cluster does not restore them: a worker's backup must carry
  `ca/`, `export/`, `local.env` and `certs/` together, since the start checks the pairs against that CA. See the
  [worker node backup](../backup-restore.md#worker-node-backup).
- **Only a master seeds `rbac.db`.** The Server API runs on the master, so a worker seeds and publishes nothing.
  When the configuration cannot say which role the node has, nothing is seeded and the start refuses
  (`INVALID … cannot read cluster.node_type`).
- **`rbac.db` is not replicated**, and an existing one is never touched. A node promoted to master serves its own
  database, seeded when it is promoted if it holds none. Supply the same `WAZUH_MANAGER_API_PASSWORD` and
  `WAZUH_MANAGER_WUI_PASSWORD` on every node, so a promoted node comes up with the passwords you already know.

`rbac_control change-password` changes the current master's database; see
[Server API authentication](../modules/server-api/authentication.md).

## Container images

An image built by installing the package carries what its `postinst` resolved: a seeded `rbac.db`, a minted CA
**with its private key**, and issued pairs. Every container started from it would share them. Clear them at the
end of the build, and resolve each container's own before its first start:

```dockerfile
# end of the Dockerfile: ship an image with no credentials of its own
RUN /var/wazuh-manager/bin/wazuh-manager-resolve-credentials --clear
```

```bash
# entrypoint, before the first start; a restarted container that already resolved changes nothing
/var/wazuh-manager/bin/wazuh-manager-resolve-credentials --install
```

`--clear` refuses while any manager daemon runs: a pid file in `var/run` that names a live process blocks it.
It removes:

- the two server pairs and `certs/root-ca.pem`;
- the indexer files that carry an import marker, and their markers;
- the CA in `ca/`, only when its mint marker is there;
- the contents of `export/`;
- `rbac.db`;
- the keystore's contents.

It keeps a CA you staged, indexer files you staged and `local.env`, and says so for each:

```text
resolve-credentials: kept /etc/wazuh-manager/certs/indexer-ca.pem: staged, no import marker
resolve-credentials: removed /etc/wazuh-manager/ca/root-ca.key
resolve-credentials: removed /var/wazuh-manager/api/configuration/security/rbac.db
resolve-credentials: every Server API user, role and policy it held is gone, not only the default users
resolve-credentials: kept /etc/wazuh-manager/local.env
resolve-credentials: cleared; the next --install resolves from nothing
```

> [!WARNING]
> `rbac.db` holds **every** Server API user, role, policy and rule, not only the two default users. Nothing is
> removed when any entry is unsafe, and a removal that fails makes the run exit `1` without the `cleared` line:
> check the exit status in a `Dockerfile`. The Server API's token signing keys
> (`api/configuration/security/private_key.pem`, `public_key.pem`) are not credentials the resolver made and stay.

## Upgrades and removal

An upgrade (`--upgrade`) never reseeds an existing `rbac.db`, never replaces a stored indexer password, and never
mints a CA or issues a pair. It completes what this host never had and imports the indexer's files when they
changed. A pair you replaced with your own PKI's survives every upgrade.

| Command | `/etc/wazuh-manager` |
|---------|----------------------|
| `apt remove wazuh-manager` | kept, every file renamed to `<name>.save`: `ca/root-ca.key` and `local.env` included |
| `apt purge wazuh-manager` | removed, with the service account |
| `rpm -e wazuh-manager` / `dnf remove` | kept as `*.save`, owned by `root:root` |

The resolver never reads a `*.save` file. A reinstall after `apt remove` finds no `certs/remoted.pem` and resolves
as an install. Delete the `.save` copies of the CA key and of `local.env` when you no longer need them.

## Rotation

To change a Server API password on a running deployment:

```bash
sudo /var/wazuh-manager/bin/rbac_control change-password
```

Neither `rbac_control` nor the Server API (`PUT /security/users/{user_id}`) updates `<CONF>/export/credentials.env`,
so the value there is stale after a change: `rbac.db` is the only authority once it is seeded.
Rotating the manager's CA means staging the new one in `ca/`, adding it to `certs/root-ca.pem` for the agents (see
[CA rotation](../modules/remoted/ca-rotation.md)); the next start publishes it in `export/ca.pem`.
