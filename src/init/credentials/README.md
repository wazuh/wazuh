# Wazuh credential and manager certificate helpers

POSIX shell libraries; source both files from root-run install/pre-start scripts.
Download/pin matching versions at package build time, but generate secrets only
on the installed host (never in a package or container image build).

**Only one of the two lives here.** `wazuh-manager-certificates.sh` is the
manager's and is in this directory. `wazuh-credentials.sh` is shared with the
indexer and the dashboard — all three resolve against the same
`/etc/wazuh/credentials.env`, so all three must agree on it exactly — and is
owned by
[wazuh-installation-assistant](https://github.com/wazuh/wazuh-installation-assistant)
under `credentials_lib/`. `make deps` downloads it to
`src/external/wazuh-credentials/`; it is not committed here, because a copy in
this repository is a copy that can drift.

## Paths

| Resolver / setting | Default | Meaning |
| --- | --- | --- |
| `wazuh_base_get_dir` / `WAZUH_BASE_DIR` | `/etc/wazuh` | Shared private bootstrap directory |
| `wazuh_env_get_file` | `<base>/credentials.env` | Operator and managed environment values |
| Lock | `<base>/.credentials.lock` | All packages must use the same base |
| `wazuh_ca_get_dir` / `WAZUH_CA_DIR` | `<base>/ca` | CA certificate and optional signing key |
| `WAZUH_MANAGER_HOME` | `/var/wazuh-manager` | Service installation directory |
| `WAZUH_MANAGER_CERT_DIR` | `<manager-home>/etc/certs` | Runtime certificate destination |

`WAZUH_BASE_DIR` is a process setting only: reading it from the file whose
location it determines would be circular. `WAZUH_CA_DIR` and the SAN settings
use **process environment > credentials.env > default**. Explicitly empty
settings are errors, not defaults. `WAZUH_CA_DIR` does **not** move the ENV file.
Only the base resolver contains the literal default path in executable code.

Writers create missing parents and targets. Existing insecure directories are
rejected, not repaired. No symlinks, relative paths or writable ancestors are
accepted. In particular, do not put bootstrap credentials under `/tmp`, even in
a private subdirectory: `/tmp` itself is writable by other users.

The base and CA are `root:root 0700`; ENV/lock are `0600`, CA certificate `0644`,
CA private key `0400`. Newly created manager parent directories are
`root:<service-group> 0750`, while `certs` is `1770` to match the existing
manager contract. Its ancestors must remain root-owned and not group/world
writable; their traversal permissions must also allow the service to reach it.
The service user/group must exist before issuance; no accounts are created.

## In this repository

`resolve-credentials.sh`, beside the certificate helper, is the manager's consumer of both: it adds
only which keys the manager owns (`WAZUH_MANAGER_API_PASSWORD`, `WAZUH_MANAGER_WUI_PASSWORD`) and
which it consumes (`WAZUH_INDEXER_MANAGER_PASSWORD`), and delegates everything else to them.

### Getting the shared half

`make -C src deps TARGET=manager` downloads it, through the `CREDENTIALS_LIB_*` rule in
[`src/Makefile`](../../Makefile) — the same ref-fallback the indexer templates use:
`tools/get_git_refs.sh` reports *this* repository's refs and the rule walks them until one resolves
against `wazuh-installation-assistant`, so a branch that exists only here 404s and falls through to
`refs/heads/<version>` from `VERSION.json`. Server targets only; an agent resolves no credentials.

Nothing degrades quietly when it is absent. `InstallServer()` aborts the installation, and both test
suites exit non-zero, each naming the `make` command that fetches it. To point them at a working
copy instead — reviewing a change to the shared half before it merges upstream — set
`WAZUH_SHARED_HELPER_DIR`, which `resolve-credentials.sh` and both suites honour.

### What gets installed

`InstallServer()` in `../inst-functions.sh` installs the three files into the *installation prefix*
rather than a fixed system path, so that parallel installs under different `USER_DIR` values do not
collide and so the files fall inside the tree `.github/actions/check_files/manager_base.csv` pins.
The two halves are apart in the source tree and together once installed:

| Source | Installed as | Mode |
| --- | --- | --- |
| `resolve-credentials.sh` | `<manager-home>/bin/wazuh-manager-resolve-credentials` | `0750 root:wazuh-manager` |
| `../../external/wazuh-credentials/wazuh-credentials.sh` (downloaded) | `<manager-home>/lib/wazuh-credentials.sh` | `0640 root:wazuh-manager` |
| `wazuh-manager-certificates.sh` | `<manager-home>/lib/wazuh-manager-certificates.sh` | `0640 root:wazuh-manager` |

It runs in four modes:

| Mode | Called from | Passwords, keystore | Certificates |
| --- | --- | --- | --- |
| `--install` | DEB `postinst` / RPM `%post` / `install.sh`, **fresh install only** | resolve | **issue** (`wazuh_manager_certificates_ensure`) |
| `--upgrade` | the same three, when a previous version was installed | resolve | untouched |
| `--prestart` | `resolvecredentials()` in `../wazuh-server.sh` — that is, `wazuh-manager-control start`, which is what the unit's `ExecStart` runs, and `restart`/`reload` after the daemons are stopped | resolve, fail naming the key | untouched |
| `--clear` | nothing in the product | remove | remove |

Each caller already knows which of the first two applies: `$2` is empty in a DEB `postinst
configure` on a fresh install, `$1` is `1` in an RPM `%post`, and `install.sh` has `update_only`.

`install.sh` skips the call entirely under `USER_RESOLVE_CREDENTIALS="n"`, which the DEB and RPM
recipes set — they run it to stage a tree they then copy into the package, and resolving there would
put one build host's `rbac.db`, bootstrap CA private key and certificates inside an artifact every
deployment installs. Both recipes also delete those paths after the staging install, so a future
change that starts generating something new cannot leak it either; on RPM the unpackaged-files check
turns the leak into a build failure, and on DEB nothing would.

**Why certificates leave the ladder after the install.** Issuing one is a signature, not a lookup,
so every later run that re-examined them would have to re-derive the chain — which means the CA
directory has to still be there, still hold the anchor the material was issued from, and still match
it byte for byte. That makes `$WAZUH_CA_DIR` a standing dependency of the manager, and a deployment
running on its own PKI has no reason to satisfy it: it stages a pair and keeps no root CA copy on
every node. They are also the one credential an operator legitimately replaces out of band, so
re-running the ladder over someone else's material can only produce false verdicts about it.

Little is lost by stopping, and it is worth being exact about how little. Against the files as they
are at start: `wazuh-manager-conf validate` checks that `remote.https.*` and `auth.ssl_*` **exist**
(as root, so it says nothing about whether the service user can read them), `remoted` then probes
its own pair with `access(R_OK)` **after** dropping privileges
(`w_remoted_check_tls_files()`), and the TLS handshake decides the rest.

The gap is the Indexer Connector pair, and it is wider than the validator's exclusion alone.
`semantics.cpp` deliberately keeps `indexer.ssl.*` out of its file list so that a manager without an
indexer can still start, and its comment says the connector reports those files at runtime. The
connector reports *one* of them: `buildSecureCommunication()` calls `std::filesystem::exists()` on
`certificate_authorities` and throws when it is absent. `certificate` and `key` are read from the
configuration and handed to the TLS layer **unchecked** — no existence test, and nowhere any
readability test, since `exists()` is a stat and not `access(R_OK)`.

So an `indexer-connector-key.pem` that is missing, or present and unreadable by `wazuh-manager`,
passes every root-side check and every check the connector makes, and surfaces from the TLS layer at
the first indexer request. `wazuh_manager_certificates_ensure()` does check the ownership and mode of
**both** pairs at installation, and more strictly than remoted's runtime probe, so material this
helper issued is right by construction; material provisioned by hand, or whose mode drifted
afterwards, is not covered until it is used. The missing piece is an existence-and-`access(R_OK)`
preflight for that pair after the privilege drop, matching `w_remoted_check_tls_files()`.

`--clear` removes every credential the manager owns or stores so a following `--install` resolves
from nothing. It is for an image built by installing the package, whose `postinst` baked this host's
credentials into a layer every container would share; the two are a pair, since only `--install`
issues certificates. It refuses while the manager is running, and keeps a CA directory that holds
only an anchor.

## Integration

Run as root; adjust helper paths for your package's private copies:

```sh
export WAZUH_BASE_DIR=/opt/wazuh-bootstrap
# Optional independent relocation:
# export WAZUH_CA_DIR=/opt/wazuh-pki/ca

. /var/wazuh-manager/lib/wazuh-credentials.sh
. /var/wazuh-manager/lib/wazuh-manager-certificates.sh

printf 'Base: %s\nENV: %s\nCA: %s\n' \
    "$(wazuh_base_get_dir)" "$(wazuh_env_get_file)" "$(wazuh_ca_get_dir)"

wazuh_env_set WAZUH_MANAGER_REMOTED_CERT_SANS \
    'DNS:agents.example.com,IP:192.0.2.10,IP:2001:db8::10' || exit 1

# The manager calls this at install time only -- see the mode table above.
wazuh_manager_certificates_ensure || exit 1
```

`wazuh_manager_certificates_ensure` finishes by running the whole of
`wazuh_manager_certificates_validate`, so a successful `ensure` already means a full validation
passed and calling both in sequence repeats roughly thirty-five `openssl` invocations for no added
coverage. Call `validate` on its own when you want to check without creating anything (a health
check, a diagnostic); do not call it after `ensure`. The manager calls neither at service start.

At package install time, the caller must handle failure without aborting the
package transaction. The libraries return nonzero but do not decide that policy.
Use an explicit `if` when sourcing from scripts with `set -e`:

```sh
if wazuh_manager_certificates_ensure; then
    :
else
    : # Report it and carry on; do not abort the transaction, and do not start or enable services
      # here. The manager has no certificates, and says so at start.
fi
```

CA and leaf issuance are serialized with ENV writes. Existing complete pairs
are verified and preserved. Partial pairs, wrong keys, wrong trust anchors,
invalid permissions and expired certificates fail without automatic rotation.
Each file is published without overwriting existing targets; a power loss
between the two files can leave a partial pair that requires operator recovery.
There is no multi-file transaction or power-loss durability guarantee.

ENV `set/unset` changes only the managed block; repeated managed keys collapse
to one assignment. Reads use the last assignment, including managed values.
ENV values are parsed as data, never executed. Use single-line values and a
newline-terminated file. For a file lacking its final newline, writes fail
rather than changing operator bytes outside the managed block.

Capture secret-returning functions (`password=$(wazuh_password_generate)`),
never run with shell xtrace around secrets, and publish only credentials your
component owns. Do not use `wazuh_env_set` as a password rotation mechanism.

## SAN and cryptographic behavior

- Indexer Connector: `clientAuth`, RSA-2048/SHA-256, 3650 days.
- Remoted/Authd: `serverAuth`, RSA-2048/SHA-256, leaf plus CA chain, notBefore
  backdated one day, notAfter 3650 days ahead. Trust-chain validity is still
  limited by CA validity; a newly created CA is not backdated.
- `WAZUH_MANAGER_CERT_SANS` configures the connector.
- `WAZUH_MANAGER_REMOTED_CERT_SANS` configures Remoted. Explicit values replace
  discovery; loopback is appended to them. Absent values include every **global-scope** IPv4/IPv6 address
  reported by `ip -o addr show` — including addresses on interfaces that are not
  on the default route, that are virtual, or that are down — plus hostname/FQDN
  and loopback. Tentative/DAD-failed addresses are excluded, and so are
  link-local and host scope: a peer can never match a `fe80::` SAN, and an
  EUI-64 one carries the interface MAC into a certificate served to every agent.
  No DNS or network connectivity is verified.
- Discovery failure is an error, not a silent loopback-only fallback. Supply
  explicit SANs if netlink is unavailable. Wildcard DNS, scoped IPv6 and CIDRs
  are rejected; equivalent textual IPv6 addresses are deduplicated.
- Complete existing pairs win over SAN inputs. Changing SANs does not renew or
  regenerate anything. CA-only deployments require pre-issued missing leaves.
- The CA private key is never copied into the service directory.

## Tests

Dependencies: OpenSSL, GNU coreutils (`stat`, `date`, `ln -T`, etc.), util-linux
`flock`, iproute2, `getent`, `hostname`, and a POSIX shell with awk/sed/grep.

Upstream expects the suite beside both helpers, in one directory. Here it lives
with the other `src/init` shell tests, and the helpers are not even in the same
place as each other, so it resolves them through two variables instead of
upstream's one: `WAZUH_HELPER_DIR` (the certificate half, defaulting to
`../credentials`) and `WAZUH_SHARED_HELPER_DIR` (the downloaded half, defaulting
to `../../external/wazuh-credentials`). Each falls back to the suite's own
directory, which is the upstream layout, so a verbatim upstream copy still runs
unchanged. That resolution block is the only local modification to the file.

```sh
sudo sh ../tests/test-wazuh-helpers.sh
sudo env TEST_SHELL=/bin/dash sh ../tests/test-wazuh-helpers.sh
sudo env TEST_SHELL=/bin/bash TEST_PIPEFAIL=1 sh ../tests/test-wazuh-helpers.sh
```

`../tests/test_resolve_credentials.sh` covers `resolve-credentials.sh` on top of
these helpers: the ladder, the two moments, and what it reports when a credential
is missing. It also requires root, for the same reason.

The suite runs each case in a separate `set -eu` shell, creates an isolated
`/root/wazuh-helper-tests.XXXXXX`, and never changes `/etc/wazuh` or the manager
installation. It uses `root:root` as a test-only service identity. Override the
test parent with `WAZUH_TEST_PARENT` only to another secure root-owned directory.
Artifacts and a private `test.log` are retained at the printed location for
inspection; they contain disposable test keys. Remove that exact directory
manually after inspection. Nothing is automatically removed outside temporary
files owned by the helpers.

Covered: paths, creation of missing ancestors, environment round trips and
precedence, operator preservation, malformed blocks, missing final newline,
permissions/symlinks, concurrent writes/issuance, password constraints,
CA-only and orphan-key states, chain/EKU/hostname verification, idempotence,
invalid SANs, canonical IPv6, simulated all-interface discovery, discovery
failure, mismatched keys and existing material with a missing shared CA.

This is not a live Wazuh, RPM/DEB, SELinux or real-network integration suite.
The interface test deliberately stubs `ip` for deterministic coverage.
The libraries retain stderr diagnostics rather than introducing a permanent
log holding secrets. Only the test runner writes `test.log`.
