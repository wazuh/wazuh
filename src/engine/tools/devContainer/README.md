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
Initializes the E2E environment by running three steps in order:

1. **Artifact download** — uses the GitHub CLI to find the latest successful build in `wazuh/wazuh-indexer` and `wazuh/wazuh-dashboard` and downloads the `.deb` packages into `wazuh-indexer/` and `wazuh-dashboard/` respectively.
2. **Certificate generation** — downloads `wazuh-install.sh` from the official Wazuh 4.x repository, generates a temporary `config.yml`, runs `--generate-config-files` to produce the cert bundle, extracts it into `certs/`, and cleans up all temporary files. If `certs/` already exists the script prompts whether to regenerate.
3. **Logging** — all output is mirrored to `init.log` in the same directory.

**Prerequisites:**
- GitHub CLI (`gh`) must be installed and authenticated (`gh auth login`)

**Usage:**
```bash
cd e2e
./init.sh
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
Deploys generated certificates to an existing wazuh-manager installation:
- Copies SSL/TLS certificates from `e2e/certs/` to `/var/wazuh-manager/etc/certs/`
- Sets appropriate ownership (`wazuh-manager:wazuh-manager`) and permissions (640)
- Maps certificate files to wazuh-manager expected names:
  - `wazuh-1-key.pem` → `manager-key.pem`
  - `wazuh-1.pem` → `manager.pem`
  - `root-ca.pem` → `root-ca.pem`
- Updates `ossec.conf` with indexer configuration

**Important:** Must be executed after installing wazuh-manager and before starting the service.

**VS Code Task:** Available as "E2E Scripts: Copy wazuh-manager certs" in the task menu (`Ctrl+Shift+P` → `Tasks: Run Task`)

### purge_wazuh.sh
Use the repo-level `tools/purge_wazuh.sh` script before re-running the E2E setup if you need to reset a local Wazuh installation completely.

**VS Code Task:** Available as "Scripts: Purge Wazuh installation" in the task menu


## Additional Resources

- **VS Code Tasks**: Pre-configured build, test, and utility tasks are available in `.vscode/tasks.json`
- **Launch Configurations**: Debug configurations available in `.vscode/launch.json`
- **Engine Documentation**: See `wazuh/src/engine/docs/` for detailed engine architecture and API documentation
