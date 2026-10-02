## PyServer development environment

> [!Warning]
> This is a testing environment, do not use in production.

This folder contains a Docker Compose development environment for the Wazuh 5.x manager's Python components (API,
framework and cluster). `docker-compose.yml` defines the following services:

| Service | Role | Host port |
|---------|------|-----------|
| `wazuh.base` | Base image (`wazuh-base`): clones `WAZUH_BRANCH` from GitHub and runs `make deps` | — |
| `certs.generator` | One-shot job that generates the certificates shared through the `wazuh-certs` volume | — |
| `wazuh.indexer` | Wazuh indexer (`quay.io/wazuh/wazuh-indexer:5.0.0-0`) | `9200` |
| `wazuh.manager` | Master node (`NODE_NAME=wazuh.manager`) | `55050` → API `55000` |
| `wazuh.worker1` | Worker node #1 | `55051` → API `55000` |
| `wazuh.worker2` | Worker node #2 | `55052` → API `55000` |
| `nginx.lb` | NGINX load balancer distributing agent connections among the nodes | `1514` |
| `wazuh.agent` | Agent, connected through `nginx.lb` | — |
| `wazuh.dashboard` | Wazuh dashboard | `443` → `5601` |

The manager image installs the branch cloned by `wazuh-base`, not your working tree. What comes from your working
tree are the Python sources, bind-mounted over the installed ones on every node: `framework/scripts`, `api/scripts`,
`framework/wazuh` and `api/api` under `${WAZUH_LOCAL_PATH}`. Changes to them take effect when the Python daemons are
restarted inside the container.

### Environment variables

Fill in `.env` before building:

| Variable | Value |
|----------|-------|
| `WAZUH_BRANCH` | Branch cloned into the base image (it must exist on GitHub) |
| `WAZUH_VERSION` | Full Wazuh version, passed to the agent's entrypoint |
| `WAZUH_PYTHON_VERSION` | `<major>.<minor>` of the embedded Python (`framework/.python-version`), used in the bind-mount paths |
| `WAZUH_LOCAL_PATH` | Absolute path to your local `wazuh` repository |

The API users' passwords are supplied to the credential resolver through `WAZUH_MANAGER_API_PASSWORD` and
`WAZUH_MANAGER_WUI_PASSWORD`, taken from `WAZUH_API_PASSWORD` and `WAZUH_WUI_PASSWORD` when they are set in `.env`
or the shell, and defaulting to `WazuhApi.2026` and `WazuhWui.2026`. The manager's entrypoint stores
`wazuh-manager`/`wazuh-manager` as the indexer credentials in the keystore, and on the master raises the API's
`max_request_per_minute` and `max_unauthenticated_request_per_minute` to `99999`.

### Working with docker environment

To run the whole cluster:

1. Run `docker compose build`
2. Run `docker compose up`

To query the master's API from the host:

```bash
curl -k -u wazuh:WazuhApi.2026 -X POST "https://localhost:55050/security/user/authenticate"
```

If a single manager container is needed:

1. Build the base image first, since the manager image is built `FROM wazuh-base`:
   `docker compose build wazuh.base`
2. Build the manager image from this folder: `docker build -t wazuh-manager --target server ./wazuh-manager`
3. Export the variables of `.env` in your shell.
4. Run it (it waits until `root-ca.pem` exists in `/var/wazuh-manager/etc/certs`, so provide the certificates, for
   example by mounting the `wazuh-certs` volume the compose project creates):

```bash
docker run -d \
--name wazuh-master \
--hostname wazuh-master \
-e NODE_NAME=wazuh-master \
-p 55000:55000 \
-v ${WAZUH_LOCAL_PATH}/framework/scripts:/var/wazuh-manager/framework/scripts \
-v ${WAZUH_LOCAL_PATH}/api/scripts:/var/wazuh-manager/api/scripts \
-v ${WAZUH_LOCAL_PATH}/framework/wazuh:/var/wazuh-manager/framework/python/lib/python${WAZUH_PYTHON_VERSION}/site-packages/wazuh \
-v ${WAZUH_LOCAL_PATH}/api/api:/var/wazuh-manager/framework/python/lib/python${WAZUH_PYTHON_VERSION}/site-packages/api \
wazuh-manager \
/scripts/entrypoint.sh wazuh-master master-node master
```

The entrypoint's third argument is the node role: `master` selects the XML overlay
`wazuh-manager/xml/master_wazuh-manager_conf.xml`, and any other value (or none, as the compose workers pass) selects
`worker_wazuh-manager_conf.xml`; the overlay is merged into
`/var/wazuh-manager/etc/wazuh-manager.conf`.

If more agents are needed:
`docker compose up --scale wazuh.agent=<number_of_agents>`

### Troubleshooting

- Use `--no-cache` when you have building issues:

  `docker compose build --no-cache`

- To completely clean the environment (including volumes), run:

  ```bash
  docker compose down -v
  ```
