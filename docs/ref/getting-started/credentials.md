# Credentials

The manager resolves every credential it needs through one order, applied at two moments: when the
package is installed, and again immediately before the service starts. Nothing an operator can skip
stands between a deployment and credentials unique to it.

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
| `WAZUH_MANAGER_CERT_SANS` | the manager's own certificates | **owns** them |
| `WAZUH_CA_DIR` | trust material, default `/etc/wazuh/ca` | path only, not a secret |

A credential the manager *owns* lives in its own datastore, so generating one makes it true. A
credential it *consumes* authenticates to somebody else, so inventing one would not make the peer
accept it — which is why `WAZUH_INDEXER_MANAGER_PASSWORD` can only ever be supplied, and why it is
the one key that commonly leaves a fresh manager unresolved until the indexer publishes it.

## The credentials file

`/etc/wazuh/credentials.env` is shared by the manager, the indexer and the dashboard. It is at once
the input, the handoff between components, and the record you read to find a generated password.

* `0600 root:root`, in a `0700 root:root` directory. It is refused outright — with the reason
  logged — when its ownership or mode is wrong, when it is a symlink, or when any directory above
  it is group- or world-writable.
* Plain `KEY=VALUE` lines. The file is **parsed, never sourced**: nothing in it is ever executed.
* The packages own a delimited block and nothing else. Lines you write outside it are never
  touched, reordered or reformatted, even when they carry the same key.
* Neither `/etc/wazuh` nor the file itself ships in any package.

```sh
# Written by the operator before installing
WAZUH_INDEXER_MANAGER_PASSWORD='Str0ng.Pass+01'

# >>> wazuh generated - do not edit
# Editing a value here does not change the deployment: a component that already
# holds the credential keeps it. To rotate, use wazuh-passwords-tool.sh.
WAZUH_MANAGER_API_PASSWORD='zL9dH…'
WAZUH_MANAGER_WUI_PASSWORD='cF4nP…'
# >>> end wazuh generated
```

> [!IMPORTANT]
> Editing a generated value here does not change the credential the manager already holds. Step 1
> of the order wins over the file, so the manager keeps what is in its own store and your edit has
> no effect. Use `wazuh-passwords-tool.sh` to rotate a credential in a running deployment.

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

## The password policy

Every password, supplied or generated, must be **12 to 64 characters and contain an uppercase
letter, a lowercase letter, a digit and a symbol**. This satisfies PCI DSS v4.0 requirement 8.3.6,
which asks for twelve characters with letters and digits, and matches what the Server API itself
enforces — so a value accepted here is never one the API rejects later.

Generated passwords are 32 characters drawn from `A-Z a-z 0-9 . , _ + : @ % ^ = ~ -`. Quotes,
backslash, backtick, `$`, `!` and `#` are left out deliberately, so a value is safe to paste through
shell, YAML, JSON and docker-compose interpolation without escaping.

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

Service start runs the whole order again — not merely a check — so the manager picks up whatever
became available since it was installed. When something is still missing it refuses to start and
names it. There is no repair command: fix the key and start the service again.

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

The unit gives up after three attempts in a minute and stays `failed`, rather than retrying forever
and flooding the journal.

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

Which flow applies is decided by what is in `$WAZUH_CA_DIR` (default `/etc/wazuh/ca`) — there is no
mode flag, because the presence of a private key beside the anchor is the signal:

| In the CA directory | Pair already in `etc/certs` | Result |
|---------------------|------------------------------|--------|
| nothing | no | mint a bootstrap CA, then issue both pairs from it |
| anchor + key | no | issue both pairs from the CA found |
| anchor only | yes | use both, generate nothing |
| anchor only | no | install the anchor; **unresolved**, the service will not start |

A host that was never given a CA private key cannot sign, and so cannot be where one leaks from.

To supply a pre-issued pair, place it in `etc/certs` **before** installing: that makes step 1 true,
which is why there is no key for it.

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

By default the certificate carries the hostname, the FQDN, `localhost`, the loopback addresses and
the global addresses on default-route interfaces only. Link-local ranges and non-default-route
interfaces are excluded, or a host running containers would advertise its `docker0`, `veth*` and CNI
addresses too.

`WAZUH_MANAGER_CERT_SANS` **replaces** that derived set; loopback is always appended. Wildcard names
are refused: under a shared CA, a node holding one could present a certificate for any other node.

```sh
WAZUH_MANAGER_CERT_SANS='DNS:wazuh.corp.local,IP:10.0.1.11'
```

> [!WARNING]
> A missing certificate stops the service, but a **wrong** one does not — it fails at the first peer
> connection, possibly weeks later, because the pre-start step opens no connections. Every run logs
> the SAN list and the DN it issued with; check what a node actually presents with
> `openssl x509 -in /var/wazuh-manager/etc/certs/remoted.pem -noout -text`.

The bootstrap CA is local to the host and disposable. A host that minted its own and later joins a
real cluster does not merge trust: the cluster's CA re-issues everything.

## Upgrades and removal

An upgrade takes step 1 for everything: existing values are detected and left untouched, and any key
still in the file is ignored whatever it contains. Replacing a credential on a running deployment is
rotation, not installation.

Removing the package leaves the credentials file untouched. Purging it removes only the
`WAZUH_MANAGER_*` keys, and only from inside the managed block; the file, the CA directory and
`/etc/wazuh` are removed only once no other component's keys remain.

## Rotation

Use `wazuh-passwords-tool.sh` for a coordinated change on a running deployment. A package must never
reconfigure a sibling — it is invoked by the package manager as a side effect of an unrelated action
— whereas the tool is invoked by you, at a moment of your choosing.

To change a Server API password on its own:

```bash
sudo /var/wazuh-manager/bin/rbac_control change-password
```
