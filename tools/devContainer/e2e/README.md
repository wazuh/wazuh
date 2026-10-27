# e2e stack

## Credentials file

`./init.sh` generates `.credentials.env` (gitignored, mode 0600) through `wazuh_credentials.sh`,
also on `--certs-only` re-runs. The canonical order is `./init.sh` and then `docker compose up -d`:
compose passes the file to the indexer and dashboard containers through `env_file:` (`required: false`).
`wazuh_install_manager.sh` hands its three manager keys to `install.sh`, `cluster/cluster.sh` the
indexer password to the workers, and `dashboard/capture.py` reads the indexer admin password from it.

The file holds five keys, each a 32-character password over `A-Za-z0-9.,_+:@%^=~-` with at least one
character of each class, generated with `openssl rand`: `WAZUH_INDEXER_ADMIN_PASSWORD`,
`WAZUH_INDEXER_KIBANASERVER_PASSWORD`, `WAZUH_INDEXER_MANAGER_PASSWORD`, `WAZUH_MANAGER_API_PASSWORD`
and `WAZUH_MANAGER_WUI_PASSWORD`. `wazuh_credentials.sh` with no mode creates the file when it is
missing and only validates an existing one (it never regenerates an invalid file); `--force`
regenerates every password, `--check` lists the keys present and validates, `--clear` deletes the
file, and `--file PATH` names another file. It prints one `PASS|FAIL|SKIP` line per check, never a
value, and exits 0 only when nothing failed.

A manual `docker compose up` without the file still starts, in degraded mode: the containers get none
of these passwords, and the dashboard's resolver fails (it owns no password), so its indexer and
manager connections stay unauthenticated until the file exists and the container is recreated.

## Per-component credentials

Each 5.0 package owns its credentials under its own configuration directory and never writes the
shared `/etc/wazuh` of earlier builds: its CA in `ca/`, its pairs in `certs/`, what it publishes for
its peers in `export/` (`credentials.env`, `ca.pem`) and the operator's values in `local.env`. Every
resolver reads the process environment first, so the variables compose injects win.

The stack stages one CA for everything (the e2e CA issued by `init.sh`), the way an operator brings
their own PKI:

| Component | Staged from `certs/` | Published |
|---|---|---|
| indexer | `node-1*` → `certs/indexer*.pem`, `admin*`, `root-ca.pem` (`root:wazuh-indexer 0640`) | `/etc/wazuh-indexer/export/{credentials.env,ca.pem}` |
| dashboard | `root-ca.pem` → `certs/indexer-ca.pem` and `certs/manager-ca.pem`, `dashboard*` (`root:wazuh-dashboard 0640`) | — (keystore only) |
| manager | `wazuh_copy_certs.sh`: `root-ca.pem` → `ca/root-ca.pem` (no key), `certs/root-ca.pem` and `certs/indexer-ca.pem`; `wazuh-1-remoted*` → `certs/remoted*.pem` and `certs/apid*.pem`; `wazuh-1*` → `certs/indexer-connector*.pem` (`root:wazuh-manager 0640`) | `/etc/wazuh-manager/export/{credentials.env,ca.pem,dashboard-client*.pem}` |

The resolvers refuse a staged file that is not root's or that the group or others can write
(`UNSAFE`), so the entrypoints and `wazuh_copy_certs.sh` install the files with
`install -o root -g <service group> -m 640`, never `chown` to the service account. The manager's
rules and the order of its credential checks:
[Credentials](../../../docs/ref/getting-started/credentials.md).

The file is **parsed, never sourced**: consumers split each line at the FIRST `=` (the generated
alphabet may contain `=`) and never `source` it or echo its values.
