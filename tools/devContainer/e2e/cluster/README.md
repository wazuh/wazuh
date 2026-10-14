# Cluster e2e (opt-in)

Multi-node cluster add-on for the e2e environment: the manager on the host becomes
the cluster master and worker managers run in containers. The default single-node
setup is unchanged.

## Topology

- **Master**: the manager running on the host (the one you build and debug).
  `setup-master.sh` turns it into the cluster master.
- **Worker(s)**: manager containers that join the master over the cluster port
  (1516) via `host.docker.internal`. Each one publishes its agent listeners on the
  host (see [Pinning agents to a worker](#pinning-agents-to-a-worker)).
- **No load balancer**: an agent reports to the node its configuration names.
- **Indexer/dashboard**: the base stack's containers. Each manager node connects to
  the indexer (the host master via `127.0.0.1:9200`, workers via
  `wazuh-indexer:9200`) as the `wazuh-manager` indexer user.

The workers are their own compose project, `dev-env-cluster`
(`docker-compose.yml` here), attached to the base stack's network
(`dev-env-engine_default`, declared external). The project holds no indexer or
dashboard definition, so bringing the workers up or down never recreates or removes
them, and `--no-deps` is not needed. Start the base stack first.

## Manager source (worker image)

`WAZUH_MANAGER_SOURCE` selects what the worker image runs; `init.sh` resolves it
into `node/pkg/`:

| Value | Input | Result |
|---|---|---|
| `manifest` (default) | `WAZUH_MANIFEST_URL` | Nightly manager package for the arch. |
| `local` | `WAZUH_MANAGER_DEB=/path.deb` | A local package. |
| `source` | the install at `/var/wazuh-manager` | Snapshot of the manager built on this host with the devContainer make tasks. Only an install at `/var/wazuh-manager` is taken: the worker runs it from that path and the install records absolute paths under its home (GeoIP databases in the engine store). The manager must be stopped while it is taken (`sudo /var/wazuh-manager/bin/wazuh-manager-control stop`); `setup-master.sh` starts it again. |

## Usage

```bash
cd tools/devContainer/e2e

./init.sh && docker compose up -d      # base stack: certs, credentials, indexer, dashboard
./cluster/init.sh                      # worker manager artifact + cluster key (cluster/.env)
sudo ./cluster/setup-master.sh         # turn the host manager into the cluster master
./cluster/cluster.sh up                # one worker; -n 3 for three
./cluster/cluster.sh ports             # host ports of each running worker
./cluster/cluster.sh down              # remove the workers
```

`cluster.sh up` builds the image, starts the workers, waits until they are healthy
and prints, for each worker, its node name and the host ports that reach it.

## Credentials and secrets

The worker needs two secrets, and both reach it as files mounted by compose
`secrets:` under `/run/secrets/`, never through `environment:`; `docker inspect` and
`docker compose config` show only their paths:

| Secret | Source | Use in the worker |
|---|---|---|
| `cluster_key` | `WAZUH_CLUSTER_KEY` in `cluster/.env` (the value the master was configured with) | `<cluster><key>` of the worker's configuration |
| `indexer_password` | `WAZUH_INDEXER_MANAGER_PASSWORD` in `../.credentials.env` | piped into the worker's keystore (`indexer`/`password`) |

`cluster.sh up` writes them to `cluster/.secrets/` (directory 0700, files 0600,
gitignored) and `cluster.sh down` deletes them. Only that one key is taken from the
credentials file: the other four (indexer admin and kibanaserver, Server API, WUI)
never reach the worker. This is why the worker does not use `env_file:` as the base
stack's indexer and dashboard do (`../docker-compose.yml`): an env file hands every
key in it to the container's environment, visible to `docker inspect`. Neither value
is printed, passed on a command line or logged.

## Pinning agents to a worker

The `../agents/` compose is a separate project with its own network, so its agents
reach a worker through the ports the worker publishes on the host, at
`host.docker.internal` (a SAN of the listener certificate every node shares, so no
certificate has to be reissued). With `-n N`, worker `i` gets a port from each
range below; `cluster.sh ports` prints which one:

| Listener (in the worker) | Host ports | Pins |
|---|---|---|
| HTTPS agent listener, 1517 | 15171–15179 | 5.x agents (enrollment and events) |
| Agent port, 1514 | 15141–15149 | 4.x agents (events) |
| authd, 1515 | 15151–15159 | 4.x agents (enrollment) |

**5.x agents** take the manager address from the enrollment token. Mint it **on the
master** (workers only read the token store the master syncs to them; a token minted
in a worker is overwritten by the next sync) with the worker's published HTTPS port,
and give the agent that token:

```bash
sudo ./agents/create_token.sh --env-file <scratch>/pinned.env --address host.docker.internal --port 15171
docker compose --env-file <scratch>/pinned.env -f agents/docker-compose.yml up -d --build agent_5x_centos
rm -f <scratch>/pinned.env
```

Wait until the token reaches the worker before the agent enrolls (the master syncs
`etc/enrollment_tokens.json` to the workers within seconds). The worker hands the
enrollment to the master (`Dispatching enrollment request to master node` in the
worker's log) and the agent keeps reporting to the worker: the master lists it as
`active`, and its events in the indexer carry the worker's node name in
`wazuh.cluster.node`. Until the master syncs the new key back to the worker, the
first connection is refused (401 on a 5.x agent, `(1408): Invalid ID` in the
worker's log for a 4.x one); the agent retries on its own. An agent volume that
already holds a key keeps its old manager: remove that service's volume first
(`docker compose -f agents/docker-compose.yml rm -sfv <service>` and
`docker volume rm dev-env-engine-agents_<service>_var`).

**4.x agents** take `MANAGER_HOST`, `MANAGER_PORT` and `AUTHD_PORT` from their
environment, which `../agents/docker-compose.yml` fixes to the master's ports. Run
the 4.x image with the worker's published ports instead, passing only `AUTHD_PASSWORD`
from the env file `create_token.sh` wrote (it also holds the 5.x token, which must not
end up in the 4.x container's environment):

```bash
docker run -d --name wazuh-agent-4x-pinned --hostname wazuh-agent-4x-pinned \
  --add-host host.docker.internal:host-gateway --env-file <(grep '^AUTHD_PASSWORD=' <scratch>/pinned.env) \
  -e MANAGER_HOST=host.docker.internal -e MANAGER_PORT=15141 -e AUTHD_PORT=15151 \
  -e AGENT_NAME=agent-4x-pinned dev-env-engine-agents-agent_4x_ubuntu
```

## Parameters

| Variable | Default | Purpose |
|---|---|---|
| `WAZUH_MANAGER_SOURCE` | `manifest` | Worker manager artifact source (`init.sh`). |
| `WAZUH_ARCH` | autodetected | Package architecture (`init.sh`). |
| `WAZUH_CLUSTER_KEY` | generated | Shared cluster key, kept in `cluster/.env`. An exported value replaces the stored one in `init.sh` and `setup-master.sh`, which rewrite `cluster/.env`; `cluster.sh` uses the same precedence but never writes `.env`, so a key exported only at `cluster.sh up` time will not match the master's: export it when running `setup-master.sh` too. |
| `WAZUH_CLUSTER_NAME` | `wazuh` | Cluster name of the master and the workers, kept in `cluster/.env` like the key. |
| `WAZUH_E2E_CREDENTIALS` | `../.credentials.env` | Credentials file `cluster.sh` takes the indexer password from. |
| `WAZUH_WORKER_{HTTPS,AGENT,AUTHD}_BASE` | `15171`, `15141`, `15151` | Host port of worker 1 for each listener (`cluster.sh`). |

## Verifying

```bash
/var/wazuh-manager/bin/cluster_control -l                                # nodes seen by the master
docker logs -f dev-env-cluster-wazuh-worker-1                            # worker join and indexer
```

## Notes

- All manager nodes share the same certificate from the e2e bundle (`../certs`);
  indexer credentials are set in each worker's keystore, not in the config file.
- Workers reach the indexer at `wazuh-indexer:9200`; `../init.sh` already adds
  that name as a DNS SAN on the indexer certificate, so hostname verification
  passes with the shared bundle.
- Managers with the same `cluster.name` write documents with the same ids into the
  shared indexer; give each test its own `WAZUH_CLUSTER_NAME`.
