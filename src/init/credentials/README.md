# Wazuh credential and manager certificate helpers

POSIX shell libraries; source both files from root-run install/pre-start scripts.
Download/pin matching versions at package build time, but generate secrets only
on the installed host (never in a package or container image build).

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

`resolve-credentials.sh`, beside these helpers, is the manager's consumer of them: it adds only
which keys the manager owns (`WAZUH_MANAGER_API_PASSWORD`, `WAZUH_MANAGER_WUI_PASSWORD`) and which
it consumes (`WAZUH_INDEXER_MANAGER_PASSWORD`), and delegates everything else here.

`InstallServer()` in `../inst-functions.sh` installs the three files into the *installation prefix*
rather than a fixed system path, so that parallel installs under different `USER_DIR` values do not
collide and so the files fall inside the tree `.github/actions/check_files/manager_base.csv` pins:

| Source | Installed as | Mode |
| --- | --- | --- |
| `resolve-credentials.sh` | `<manager-home>/bin/wazuh-manager-resolve-credentials` | `0750 root:wazuh-manager` |
| `wazuh-credentials.sh` | `<manager-home>/lib/wazuh-credentials.sh` | `0640 root:wazuh-manager` |
| `wazuh-manager-certificates.sh` | `<manager-home>/lib/wazuh-manager-certificates.sh` | `0640 root:wazuh-manager` |

It is invoked from the DEB `postinst` and the RPM `%post` as `--install`, and as `--prestart` from
`testconfig()` in `../wazuh-server.sh` — that is, from `wazuh-manager-control start`, which is what
the systemd unit's `ExecStart` runs.

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

# Suitable on its own for a pre-start resolver:
wazuh_manager_certificates_ensure || exit 1
```

`wazuh_manager_certificates_ensure` finishes by running the whole of
`wazuh_manager_certificates_validate`, so a successful `ensure` already means a full validation
passed and calling both in sequence repeats roughly thirty-five `openssl` invocations for no added
coverage — about half a second on every service start. Call `validate` on its own when you want to
check without creating anything (a health check, a diagnostic); do not call it after `ensure`.

At package install time, the caller must handle failure without aborting the
package transaction. The libraries return nonzero but do not decide that policy.
Use an explicit `if` when sourcing from scripts with `set -e`:

```sh
if wazuh_manager_certificates_ensure; then
    :
else
    : # Leave resolution to pre-start; do not start or enable services here.
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
  discovery. Absent values include all assigned IPv4/IPv6 addresses reported by
  `ip -o addr show`, including non-default-route, virtual and link-local
  interfaces, plus hostname/FQDN and loopback. Tentative/DAD-failed addresses
  are excluded. No DNS or network connectivity is verified.
- Discovery failure is an error, not a silent loopback-only fallback. Supply
  explicit SANs if netlink is unavailable. Wildcard DNS, scoped IPv6 and CIDRs
  are rejected; equivalent textual IPv6 addresses are deduplicated.
- Complete existing pairs win over SAN inputs. Changing SANs does not renew or
  regenerate anything. CA-only deployments require pre-issued missing leaves.
- The CA private key is never copied into the service directory.

## Tests

Dependencies: OpenSSL, GNU coreutils (`stat`, `date`, `ln -T`, etc.), util-linux
`flock`, iproute2, `getent`, `hostname`, and a POSIX shell with awk/sed/grep.

Upstream expects the suite beside the two helpers. Here it lives with the other
`src/init` shell tests instead, and resolves the helpers through
`WAZUH_HELPER_DIR` — which defaults to `../credentials` and falls back to the
suite's own directory, so a verbatim upstream copy still runs unchanged. That is
the only local modification to the file.

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
