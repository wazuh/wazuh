# Agents E2E

This directory contains a minimal environment to run Wazuh agents inside containers and connect them to a manager reachable from the devContainer host. The goal is to validate agent-side end-to-end scenarios without depending on manual installations on separate machines.

There are currently two agent variants based on Rocky Linux 8:

- `4.14.3`: installs the package from the official Wazuh repository.
- `5.x`: installs the agent from a local RPM that must be present in the build context.

## Structure

```text
agents/
├── docker-compose.yml
└── rpm/
    ├── 4.14.3/
    │   ├── Dockerfile
    │   └── entrypoint.sh
    └── 5.x/
        ├── Dockerfile
        ├── entrypoint.sh
        └── wazuh-agent_5.0.0-0_x86_64_*.rpm
```

## Files and responsibilities

### `docker-compose.yml`

Defines two services:

- `agent_4143_rocky8`
- `agent_50_rocky8`

Both services:

- build their image from `rpm/<version>`
- add `host.docker.internal` pointing to the host gateway
- configure environment variables for agent registration
- mount a persistent volume at `/var/ossec`
- restart with the `unless-stopped` policy

The persistent volumes are:

- `agent_4143_rocky8_var`
- `agent_50_rocky8_var`

This means the agent state, keys, and configuration survive a `docker compose stop/start`. If you need a clean start, bring the environment down with volumes removed.

### `rpm/4.14.3/Dockerfile`

Builds an image based on `rockylinux:8` and:

- updates base packages
- installs required utilities such as `curl`, `hostname`, `procps-ng`, and `tini`
- imports the Wazuh GPG key
- creates the Wazuh 4.x Yum repository
- installs `wazuh-agent-4.14.3*` from the official repository
- copies `entrypoint.sh`

This variant does not require any additional local artifacts to build the image.

### `rpm/5.x/Dockerfile`

This image also starts from `rockylinux:8`, installs basic dependencies, and imports the Wazuh GPG key, but the important difference is that it does not download the agent from a repository. Instead, it:

- runs `COPY wazuh-agent_5.0.0-0_x86_64_*.rpm /tmp/`
- installs the local RPM with `dnf`
- removes the temporary file and cleans the cache
- copies `entrypoint.sh`

## RPM requirement for `5.x`

For the `agent_50_rocky8` service to build successfully, the agent RPM package must exist inside:

```text
rpm/5.x/
```

with a filename matching this pattern:

```text
wazuh-agent_5.0.0-0_x86_64_*.rpm
```

If the file is not present, the Docker build fails at the `COPY` step.

Example of a valid filename:

```text
wazuh-agent_5.0.0-0_x86_64_test.rpm
```

If the expected agent version changes, the pattern in `rpm/5.x/Dockerfile` must be updated.

### `rpm/4.14.3/entrypoint.sh` and `rpm/5.x/entrypoint.sh`

Both entrypoints implement the same flow:

1. read environment variables for connection and registration
2. update the manager address inside `/var/ossec/etc/ossec.conf`
3. run `agent-auth` to register the agent against `authd`
4. start the agent with `wazuh-control start`
5. keep the container alive by following `/var/ossec/logs/ossec.log`

Supported variables:

- `MANAGER_HOST`: manager host, default `host.docker.internal`
- `MANAGER_PORT`: manager connection port, default `1514`
- `AUTHD_PORT`: `agent-auth` registration port, default `1515`
- `AGENT_NAME`: name used to register the agent
- `AUTHD_PASSWORD`: optional password for authenticated registration

The scripts tolerate `agent-auth` failures with `|| true`. That prevents the container from exiting immediately, but it also means a container in `running` state does not guarantee that the agent was registered successfully. The real verification should be done by checking the logs.

## How to use it

### Prerequisites

- Docker must be available inside the devContainer
- a Wazuh manager must be reachable from the container host
- port `1514` must be reachable for agent connection
- port `1515` must be reachable if `authd` registration is used
- for `5.x`, the agent RPM must be copied into `rpm/5.x/` beforehand

This compose setup assumes the manager is reachable as `host.docker.internal`. That works because each service adds:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

### Start the agents

From this directory:

```bash
docker compose up -d --build
```

If your environment uses the classic binary, the equivalent command is:

```bash
docker-compose up -d --build
```

### Start a single agent

```bash
docker compose up -d --build agent_4143_rocky8
docker compose up -d --build agent_50_rocky8
```

### View logs

```bash
docker compose logs -f agent_4143_rocky8
docker compose logs -f agent_50_rocky8
```

### Force rebuild after changing the RPM

If you replace the local `5.x` agent RPM, rebuild the image:

```bash
docker compose build --no-cache agent_50_rocky8
docker compose up -d agent_50_rocky8
```

### Start from scratch

To remove the persistent `/var/ossec` state as well:

```bash
docker compose down -v
```

## Expected startup flow

When the container starts:

1. the agent is installed or already present in the image
2. the entrypoint rewrites `ossec.conf` with the manager address
3. the agent attempts to authenticate with `agent-auth`
4. the agent service is started
5. the container remains alive by following `ossec.log`

This makes it possible to quickly test:

- new agent enrollment
- compatibility across agent versions
- connectivity against a manager running on the host
- registration or communication issues by reviewing container logs

## Operational considerations

- The `5.x` service depends on a local artifact. The Dockerfile alone is not enough; the RPM must be copied into the folder before building.
- Because `/var/ossec` is mounted on a volume, an already registered agent can reuse previous state across restarts.
- If you need to test a clean enrollment, use `docker compose down -v`.
- If the manager is not running on the host or does not expose `1514/1515`, the container will start but registration and connection will not complete.
- If your deployment uses an `authd` password, define `AUTHD_PASSWORD` in the compose file or when launching the service.

## Quick customization example

To change the agent name or pass a registration password, you can modify the service environment variables in `docker-compose.yml`:

```yaml
environment:
  MANAGER_HOST: "host.docker.internal"
  MANAGER_PORT: "1514"
  AUTHD_PORT: "1515"
  AGENT_NAME: "agent-50-rocky8"
  AUTHD_PASSWORD: "secret"
```

## Required RPM location

The expected location for the local `5.x` agent package is:

```text
wazuh/src/engine/tools/devContainer/e2e/agents/rpm/5.x/
```

That file is part of the Docker build context. If it is placed outside that folder, the `Dockerfile` will not be able to copy it.