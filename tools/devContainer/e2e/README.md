# e2e stack

## Credentials file

`./init.sh` generates `.credentials.env` (gitignored, mode 0600) through `wazuh_credentials.sh`,
also on `--certs-only` re-runs. The canonical order is `./init.sh` and then `docker compose up -d`:
compose passes the file to the indexer and dashboard containers through `env_file:`.

A manual `docker compose up` without the file still starts, in degraded mode: each component
generates its own passwords, and the dashboard has no manager API password until it is re-resolved.
