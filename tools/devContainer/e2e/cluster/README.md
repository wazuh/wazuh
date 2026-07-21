# Cluster e2e (opt-in)

Multi-node cluster add-on for the e2e environment. It is an overlay on the base
`../docker-compose.yml`. The default single-node setup is unchanged.

## Topology

- **Master**: the manager running on the host (the one you build and debug).
  `setup-master.sh` turns it into the cluster master.
- **Worker(s)**: manager containers that join the master over the cluster port
  (1516) via `host.docker.internal`. They do not publish any port.
- **No load balancer**: agents are pointed at a node by hand — the master via
  `host.docker.internal`, or a worker by its container name.
- **Indexer/dashboard**: reused from the base compose. Each manager node connects
  to the indexer (the host master via `127.0.0.1:9200`, workers via
  `wazuh-indexer:9200`).

## Manager source (worker image)

`WAZUH_MANAGER_SOURCE` selects what the worker image runs; `init.sh` resolves it
into `node/pkg/`:

| Value | Input | Result |
|---|---|---|
| `manifest` (default) | `WAZUH_MANIFEST_URL` | Nightly manager package for the arch. |
| `local` | `WAZUH_MANAGER_DEB=/path.deb` | A local package. |
| `source` | `WAZUH_HOME` (default `/var/wazuh-manager`) | Snapshot of the manager built on this host with the devContainer make tasks. |

## Usage

Run from the `e2e/` directory (the compose project directory):

```bash
cd tools/devContainer/e2e

./init.sh                          # certs + indexer/dashboard packages (base)
./cluster/init.sh                  # worker manager artifact + cluster key
./cluster/setup-master.sh          # turn the host manager into the cluster master

docker compose --env-file cluster/.env -f docker-compose.yml -f cluster/docker-compose.yml up -d --build
docker compose --env-file cluster/.env -f docker-compose.yml -f cluster/docker-compose.yml up -d --build --scale wazuh-worker=3
```

## Assigning agents to nodes

The `../agents/` compose is a separate project with its own network, so it cannot
resolve the worker container names, and 5.x agents bake the enrollment target at
install time (changing `MANAGER_HOST` only rewrites `<address>`, not the
enrollment). As shipped, agents therefore enroll and report against the master on
the host (`host.docker.internal`). Pinning an agent to a specific worker is not
wired up in this overlay.

## Parameters

| Variable | Default | Purpose |
|---|---|---|
| `WAZUH_MANAGER_SOURCE` | `manifest` | Worker manager artifact source. |
| `WAZUH_ARCH` | autodetected | Package architecture. |
| `WAZUH_CLUSTER_KEY` | generated | Shared cluster key (persisted to `.env`). |
| `INDEXER_USER` / `INDEXER_PASSWORD` | `admin` / `admin` | Indexer credentials stored in the worker keystore. |

## Verifying

```bash
/var/wazuh-manager/bin/cluster_control -l              # nodes seen by the master
docker compose ... logs -f wazuh-worker                # worker join and indexer
```

## Notes

- All manager nodes share the same certificate from the e2e bundle (`../certs`);
  indexer credentials are set in each worker's keystore, not in the config file.
- Workers reach the indexer at `wazuh-indexer:9200`; `../init.sh` already adds
  that name as a DNS SAN on the indexer certificate, so hostname verification
  passes with the shared bundle.
