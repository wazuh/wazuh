# e2e stack

## Credentials file

`./init.sh` generates `.credentials.env` (gitignored, mode 0600) through `wazuh_credentials.sh`,
also on `--certs-only` re-runs. The canonical order is `./init.sh` and then `docker compose up -d`:
compose passes the file to the indexer and dashboard containers through `env_file:`.

A manual `docker compose up` without the file still starts, in degraded mode: each component
generates its own passwords, and the dashboard has no manager API password until it is re-resolved.

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
| manager | `wazuh_copy_certs.sh`: `root-ca.pem` → `ca/root-ca.pem` (no key) and `certs/indexer-ca.pem`, the listener and connector pairs | `/etc/wazuh-manager/export/{credentials.env,ca.pem,dashboard-client*.pem}` |

The resolvers refuse a staged file that is not root's or that the group or others can write
(`UNSAFE`), so the entrypoints install the files with `install -o root -g <service group> -m 640`,
never `chown` to the service account.

The file is **parsed, never sourced**: consumers split each line at the FIRST `=` (the generated
alphabet may contain `=`) and never `source` it or echo its values.
