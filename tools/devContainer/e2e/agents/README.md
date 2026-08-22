# Agents E2E

Minimal environment to run Wazuh agents in containers and connect them to a
manager reachable from the devContainer host (`host.docker.internal`). Useful to
validate enrollment, connectivity and cross-version behaviour without separate
machines.

## Structure

```text
agents/
├── docker-compose.yml
├── init.sh
├── entrypoint.sh
├── ubuntu/{4.x,5.x}/Dockerfile
├── centos/{4.x,5.x}/Dockerfile
└── pkgs/            # agent packages downloaded by init.sh
```

Four services, each on its own base image and version:

| Service | Base | Version |
|---|---|---|
| `agent_4x_ubuntu` | Ubuntu | 4.x |
| `agent_4x_centos` | Rocky Linux | 4.x |
| `agent_5x_ubuntu` | Ubuntu | 5.x |
| `agent_5x_centos` | Rocky Linux | 5.x |

Each mounts a persistent volume at `/var/ossec` (state survives restart; use
`down -v` for a clean enrollment).

## Packages (`init.sh`)

`init.sh` downloads the agent installers into `pkgs/` for the target
architecture (autodetected from `uname -m`, override with `WAZUH_ARCH=amd64|arm64`):

- 4.x deb/rpm from the production repositories.
- 5.x deb/rpm resolved from the staging nightly manifest.

Each is saved under a fixed, arch-independent name (`wazuh-agent_4x.{deb,rpm}`,
`wazuh-agent_5x.{deb,rpm}`) that the Dockerfiles install by exact name, so a
re-run for a different arch overwrites the previous package. Requires `curl` and `yq`.

## Registration

- **5.x** agents have no `agent-auth`. The manager address and the enrollment
  password are configured at **install time** from the `WAZUH_MANAGER` and
  `WAZUH_REGISTRATION_PASSWORD` build args (the package post-install writes the
  `<enrollment>` block with `authorization_pass_path`), so the agent enrolls
  automatically on start.
- **4.x** agents register at runtime with `agent-auth`, using `AUTHD_PASSWORD`.

`WAZUH_REGISTRATION_PASSWORD` / `AUTHD_PASSWORD` is the manager's enrollment
password, i.e. the contents of its `etc/authd.pass`.

## Usage

```bash
cd tools/devContainer/e2e/agents

./init.sh                        # download agent packages for this arch

# WAZUH_REGISTRATION_PASSWORD must equal the manager's etc/authd.pass
export WAZUH_REGISTRATION_PASSWORD="$(sudo cat /var/wazuh-manager/etc/authd.pass)"

docker compose up -d --build                    # all agents
docker compose up -d --build agent_5x_ubuntu    # a single agent
docker compose logs -f agent_5x_ubuntu          # follow its log
docker compose down -v                          # stop and wipe state
```

## Notes

- A container in `running` state does not guarantee successful enrollment; verify
  with the agent log (`Valid key received` / `Connected to the server`) and the
  manager's `etc/client.keys`.
- The manager must be reachable at `host.docker.internal:1514` (reporting) and
  `1515` (enrollment); each service adds `host.docker.internal:host-gateway`.
