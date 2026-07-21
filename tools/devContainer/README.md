# Engine Development Container

This development container provides a complete, ready-to-use environment for developing and testing the Wazuh Engine. It includes all necessary tools, dependencies, and pre-configured VS Code settings to streamline the development workflow.

## Features

- **Complete Build Environment**: Includes all required dependencies to compile the Wazuh engine from source (GCC, CMake, Python, Go, Docker CLI, and more)
- **IDE Integration**: Pre-configured VS Code settings, tasks, and launch configurations for debugging and development
- **Docker-in-Docker**: Full Docker support for running containerized services within the development environment
- **Development Tools**: Git, GitHub CLI, SSH server, and various development utilities pre-installed
- **Python & Go Support**: Configured Python and Go environments for extending engine functionality

## Getting Started

### Prerequisites

The following tools must be installed and running on your system before using the download script:

- **Docker**: Must be installed and the Docker daemon must be running
- **Git**: Must be installed

> [!NOTE]
> If your user is not in the `docker` group, the script will warn you and you may need `sudo` privileges.

### Quick Start

Download and set up the development container:

```bash
curl -o download_devContainer.sh https://raw.githubusercontent.com/wazuh/wazuh/main/src/engine/tools/devContainer/download_devContainer.sh
chmod +x download_devContainer.sh
./download_devContainer.sh -h
```

**Options:**
- `-d <destination>`: Specify destination directory (default: `./devContainer`)
- `-b <branch>`: Specify Git branch to download from (default: `main`)
- `-h`: Show help message

**Example:**
```bash
./download_devContainer.sh -d ~/wazuh-engine-dev -b development
```

> [!NOTE]
> The destination directory must not already exist — the script exits with an error if it does.

> [!NOTE]
> After the download completes, the script will interactively ask whether you want to open the devContainer in VS Code. If VS Code and the Remote - Containers extension are available, it will open the workspace automatically; otherwise it will print a warning to open manually.

> [!NOTE]
> This setup currently only works on Linux systems.

### What gets downloaded

The script downloads only the core devContainer configuration:

```
devContainer/
├── .devcontainer/    # Dockerfile and devcontainer.json
└── .vscode/          # VS Code tasks, launch, and settings
```

The `scripts/` and `e2e/` directories are **not** included in the download. They are available in the full Wazuh repository under `src/engine/tools/devContainer/`.


## Development Utilities (scripts/)

> [!NOTE]
> The `scripts/` directory is not downloaded by `download_devContainer.sh`. It is available in the Wazuh repository at `src/engine/tools/devContainer/scripts/`.

The `scripts/` directory contains various utilities to facilitate engine development and testing:

### create_struct_standalone.sh
Creates the directory structure required for running the engine in standalone mode:
- Sets up store directories for schemas and configurations
- Creates log, timezone database (tzdb), and key-value database (kvdb) directories
- Initializes queue and output directories for connectors
- Copies necessary schema files from the engine source

### mount_wazuh_proc.sh
Mounts the `/proc` filesystem inside the Wazuh installation directory for development and testing purposes.

### toggle_event_dumper.sh
Enables or disables the event dumper functionality in the Wazuh engine.

### pr-clang.sh
Formats (or checks formatting of) all `.cpp`/`.hpp` files changed in the current PR against `src/engine/source/`. Accepts an optional `--check` flag to only verify without modifying files.

### wazuh-certs-tool.sh / wazuh-certs-tool.yml
Devcontainer copy of the installation assistant's certificate tool (`wazuh-certs-tool-5.0.0-beta5.sh`). The script header records the origin URL, its sha256 and the numbered list of local changes; every changed hunk is marked `# DEVCONTAINER:`, so `diff <(curl -sSL <origin URL>) wazuh-certs-tool.sh` is a readable patch. Driven by `wazuh-certs-tool.yml` (`nodes.indexer|manager|dashboard[] {name, ip, dns}`, the same shape as the assistant's `config.yml`), it issues:
- `root-ca.pem` / `root-ca.key` — or reuses the pair passed after `-A` — and `admin.pem` / `admin-key.pem`
- `<name>.pem` / `<name>-key.pem` per indexer, manager and dashboard node, with the assistant's unchanged DNs (the indexer package pins `CN=node-1,OU=Wazuh,O=Wazuh,L=California,C=US`)
- per manager node, additionally **`<name>-remoted.pem`** — the agent-listener leaf followed by the CA (`basicConstraints critical CA:FALSE`, `keyUsage critical digitalSignature,keyEncipherment`, `extendedKeyUsage serverAuth`, SAN = `ip` + `dns` + `<name>`, RSA 2048, SHA-256, 3650 days) — and **`<name>-remoted-key.pem`**, verified with `openssl verify -CAfile root-ca.pem` before the tool exits

```bash
bash scripts/wazuh-certs-tool.sh -A -v -c scripts/wazuh-certs-tool.yml -o /path/to/out                  # new CA
bash scripts/wazuh-certs-tool.sh -A ca.pem ca.key -c scripts/wazuh-certs-tool.yml -o /path/to/out -f    # reuse a CA, write into a non-empty dir
```

The output directory is 755 with private keys 600 and certificates 644, plus `config.yml` (LF copy of the input YAML) and `wazuh-certificates-tool.log`; a non-empty output directory is refused unless `-f` is given. The node names in the YAML are load-bearing (`node-1` for the indexer's `nodes_dn` and entrypoint, `dashboard` for its entrypoint, the first manager node for `e2e/wazuh_copy_certs.sh`); the comments in the file name the consumer that pins each one. `e2e/init.sh` is the normal caller.

### Other utilities
- `event_sock_v2.go`: Tools for testing event socket communication
- `wazuh_stream_socket.go`: WebSocket streaming utility for engine events

### purge_wazuh.sh
Located at `tools/purge_wazuh.sh` (Wazuh repository root), this script provides a comprehensive cleanup for local Wazuh manager/agent installations:
- Removes Wazuh packages via apt-get or yum
- Supports `dnf`, `yum`, `zypper`, and `rpm`-based package removal
- Unmounts proc filesystem if mounted for development
- Stops and removes Wazuh services
- Cleans up all Wazuh-related files and directories
- Removes Wazuh user and group from the system
- Falls back to a full filesystem cleanup when the installation was created from sources instead of packages

## E2E Testing Environment

> [!NOTE]
> The `e2e/` directory is not downloaded by `download_devContainer.sh`. It is available in the Wazuh repository at `src/engine/tools/devContainer/e2e/`.

The `e2e/` directory provides scripts to deploy a complete Wazuh ecosystem for end-to-end testing and development within the devContainer.


### init.sh
Initializes the E2E environment by running these steps in order:

1. **Package download** (skipped with `--certs-only`) — downloads the Wazuh Indexer and Dashboard `.deb` packages into `wazuh-indexer/` and `wazuh-dashboard/` respectively. By default, package URLs are resolved from the staging nightly manifest, falling back to the nightly backup manifest when a package is missing. Use `--from-wf` to download from the latest successful GitHub Actions workflows instead.
2. **Certificate generation** — runs `scripts/wazuh-certs-tool.sh -A -v -c scripts/wazuh-certs-tool.yml -o certs/` (see [wazuh-certs-tool.sh](#wazuh-certs-toolsh--wazuh-certs-toolyml)) and post-checks the result: the files the docker entrypoints and `wazuh_copy_certs.sh` copy by name exist, every leaf passes `openssl verify -CAfile certs/root-ca.pem`, and the SAN/EKU/KU/BC of the agent-listener leaf are printed. If `certs/` already exists the script prompts before replacing it (`--regen-certs` skips the prompt). The existing `certs/root-ca.pem` / `root-ca.key` are **reused** so the indexer/dashboard containers and the installed manager keep trusting the same CA; `--rotate-ca` issues a new CA instead, after which everything that trusted the old one must be redeployed (`docker compose down -v && docker compose up -d`, `sudo ./wazuh_copy_certs.sh`).
3. **Manager listeners** — when a manager is installed under `WAZUH_MANAGER_HOME` (default `/var/wazuh-manager`), binds both remoted listeners to `0.0.0.0` in `etc/wazuh-manager.conf` so containerised agents can reach it.
4. **Logging** — all output is mirrored to `init.log` in the same directory.

**Prerequisites:**
- Default mode: `curl`, `openssl`
- Workflow mode (`--from-wf`): GitHub CLI (`gh`) must be installed and authenticated (`gh auth login`), `unzip`
- `--certs-only`: `openssl`

**Usage:**
```bash
cd e2e
./init.sh
./init.sh --from-wf
./init.sh --certs-only --regen-certs   # re-issue every leaf, keep the CA (VS Code task "E2E Scripts: [Manager] Regenerate certs (keep CA)")
./init.sh --certs-only --rotate-ca     # new CA: redeploy everything that trusts it afterwards
```

### docker-compose.yml
Orchestrates the E2E environment. Both images are **built locally** from their subdirectories (`./wazuh-indexer`, `./wazuh-dashboard`) using the packages downloaded by `init.sh` — they are not pulled from a registry.

**wazuh-indexer**
- OpenSearch-based search and analytics engine
- Exposed on port `9200` (HTTPS)
- Mounts certificates from `./certs` (read-only)
- Three named volumes: `wazuh-indexer-data`, `wazuh-indexer-config`, `wazuh-indexer-engine`

**wazuh-dashboard**
- Wazuh web interface for visualization and management
- Exposed on port `443` (HTTPS)
- Resolves `host.docker.internal` to the host gateway for engine communication
- Depends on `wazuh-indexer`

**Starting the environment:**
```bash
cd e2e
docker-compose up -d
```

>[!NOTE]
> If you need to update the Indexer or Dashboard packages, re-run `./init.sh` to fetch the latest artifacts before starting the services:
> ```bash
> docker-compose down
> ./init.sh
> docker-compose up -d # This rebuilds services with updated packages
> ```
> The containers copy the certificates from `./certs` at start: after `./init.sh --certs-only --regen-certs` (same CA, re-issued leaves) a plain `docker compose down && docker compose up -d` loads them. After `./init.sh --certs-only --rotate-ca` use `docker compose down -v && docker compose up -d` instead — `-v` drops the indexer volumes so its security index is re-initialised with the new admin certificate.

### agents/

The `agents/` subdirectory provides a self-contained environment to run Wazuh agents inside containers connected to a manager running on the devContainer host.

#### agents/init.sh

Downloads the four agent installer packages required by the compose services before the first build:

- `4.x .deb` (Ubuntu) and `4.x .rpm` (CentOS) — from the official Wazuh 4.x repository
- `5.x .deb` (Ubuntu) and `5.x .rpm` (CentOS) — resolved from the staging nightly manifest

Packages are saved into `agents/pkgs/` and are picked up automatically by `docker-compose` at build time.

**Prerequisites:** `curl` and `yq` must be installed.

**Usage:**
```bash
cd e2e/agents
./init.sh           # download missing packages
./init.sh --force   # re-download even if already present
```

#### agents/docker-compose.yml

Defines four agent services, all connecting to the manager on the host via `host.docker.internal`:

| Service | Image base | Agent version | Ports used |
|---|---|---|---|
| `agent_4x_centos` | CentOS | 4.x | 1514 (connect), 1515 (authd) |
| `agent_4x_ubuntu` | Ubuntu | 4.x | 1514, 1515 |
| `agent_5x_centos` | CentOS | 5.x | 1514, 1515 |
| `agent_5x_ubuntu` | Ubuntu | 5.x | 1514, 1515 |

Each service mounts a persistent volume for `/var/ossec` and restarts with `unless-stopped`. Use `docker-compose down -v` for a clean start that discards agent state.

**Usage:**
```bash
cd e2e/agents
docker-compose up -d --build        # start all agents
docker-compose up -d --build agent_5x_ubuntu  # start a single agent
```

For full details, see [agents/README.md](e2e/agents/README.md).

### wazuh_copy_certs.sh
Deploys the certificates issued by `init.sh` into an existing wazuh-manager installation (`WAZUH_MANAGER_HOME`, default `/var/wazuh-manager`). It must run as **root** (`sudo ./wazuh_copy_certs.sh`) and requires the `wazuh-manager` user and group to exist:

| Source (`e2e/certs/`) | Destination (`etc/certs/`) | Owner | Mode |
|---|---|---|---|
| `root-ca.pem` | `root-ca.pem` | `root:wazuh-manager` | 640 |
| `<node>.pem` | `indexer-connector.pem` | `root:wazuh-manager` | 640 |
| `<node>-key.pem` | `indexer-connector-key.pem` | `root:wazuh-manager` | 640 |
| `<node>-remoted.pem` | `remoted.pem` | `wazuh-manager:wazuh-manager` | 640 |
| `<node>-remoted-key.pem` | `remoted-key.pem` | `wazuh-manager:wazuh-manager` | 640 |

`<node>` is the first `- name:` under `manager:` in `scripts/wazuh-certs-tool.yml` (`wazuh-1`), overridable with `MANAGER_NODE_NAME`. `etc/certs` is created as `1770 root:wazuh-manager`, like the installer does; `root-ca.key` is never copied. remoted opens its certificate and key after dropping privileges (hence the `wazuh-manager` owner), while the indexer-connector files are read as root. The script then verifies the deployed files (`openssl verify -CAfile root-ca.pem`, expiry check) and prints the `<remote><https>` certificate settings of `etc/wazuh-manager.conf` for review — it **does not edit** the configuration: the defaults already point at `etc/certs/remoted.pem`, `etc/certs/remoted-key.pem` and `etc/certs/root-ca.pem`.

**Important:** run it after installing wazuh-manager and before starting the service, or restart it afterwards (`wazuh-manager-control restart`).

**VS Code Tasks:** "E2E Scripts: [Manager] Copy wazuh-manager certs" and, to re-issue the leaves while keeping the CA, "E2E Scripts: [Manager] Regenerate certs (keep CA)" (`Ctrl+Shift+P` → `Tasks: Run Task`)

### purge_wazuh.sh
Use the repo-level `tools/purge_wazuh.sh` script before re-running the E2E setup if you need to reset a local Wazuh installation completely.

**VS Code Task:** Available as "Scripts: Purge Wazuh installation" in the task menu


## Additional Resources

- **VS Code Tasks**: Pre-configured build, test, and utility tasks are available in `.vscode/tasks.json`
- **Launch Configurations**: Debug configurations available in `.vscode/launch.json`
- **Engine Documentation**: See `wazuh/src/engine/docs/` for detailed engine architecture and API documentation
