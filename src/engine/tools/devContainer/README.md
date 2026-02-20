# Engine Development Container

This development container provides a complete, ready-to-use environment for developing and testing the Wazuh Engine. It includes all necessary tools, dependencies, and pre-configured VS Code settings to streamline the development workflow.

## Features

- **Complete Build Environment**: Includes all required dependencies to compile the Wazuh engine from source (GCC, CMake, Python, Go, Docker CLI, and more)
- **IDE Integration**: Pre-configured VS Code settings, tasks, and launch configurations for debugging and development
- **Docker-in-Docker**: Full Docker support for running containerized services within the development environment
- **Development Tools**: Git, GitHub CLI, SSH server, and various development utilities pre-installed
- **Python & Go Support**: Configured Python and Go environments for extending engine functionality

## Getting Started

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
> This setup currently only works on Linux systems.


## Development Utilities (scripts/)

The `scripts/` directory contains various utilities to facilitate engine development and testing:

### create_struct_standalone.sh
Creates the directory structure required for running the engine in standalone mode:
- Sets up store directories for schemas and configurations
- Creates log, timezone database (tzdb), and key-value database (kvdb) directories
- Initializes queue and output directories for connectors
- Copies necessary schema files from the engine source

### purge_wazuh.sh
Comprehensive cleanup script that removes Wazuh manager/agent installations:
- Removes Wazuh packages via apt-get or yum
- Unmounts proc filesystem if mounted for development
- Stops and removes Wazuh services
- Cleans up all Wazuh-related files and directories
- Removes Wazuh user and group from the system

### mount_wazuh_proc.sh
Mounts the `/proc` filesystem inside the Wazuh installation directory for development and testing purposes.

### toggle_archive.sh
Enables or disables the archiving functionality in the Wazuh engine.

### Other utilities
- `event_sock.py`, `event_sock_v2.go`: Tools for testing event socket communication
- `wazuh_stream_socket.go`: WebSocket streaming utility for engine events
- `fix_wazuh_dash.sh`, `fix_wazuh_indexer.sh`: Helper scripts to fix common issues with dashboard and indexer

## E2E Testing Environment

The `e2e/` directory provides scripts to deploy a complete Wazuh ecosystem for end-to-end testing and development within the devContainer.


### init.sh
Initializes the complete E2E testing environment:
- **Certificate Generation**: Creates SSL/TLS certificates for secure communication between components (Wazuh API, Indexer, Dashboard)
- **Artifact Download**: Automatically locates and downloads the latest Wazuh Indexer and Dashboard packages from GitHub Actions artifacts (main branch)
- **Configuration**: Generates necessary configuration files (`config.yml`, `wazuh-passwords.txt`)
- **Environment Bootstrap**: Prepares the Docker-based environment with all required files

**Usage:**
```bash
cd e2e
./init.sh
```

### docker-compose.yml
Orchestrates the E2E environment with the following services:

**wazuh-indexer**
- OpenSearch-based search and analytics engine
- Exposed on port `9200` (HTTPS)
- Includes persistent volume support for data retention
- Pre-configured with security certificates

**wazuh-dashboard**
- Wazuh web interface for visualization and management  
- Exposed on port `443` (HTTPS)
- Configured with host network access for engine communication
- Automatically connects to wazuh-indexer

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

### wazuh_copy_certs.sh
Deploys generated certificates to an existing wazuh-manager installation:
- Copies SSL/TLS certificates from `e2e/certs/` to `/var/wazuh-manager/etc/certs/`
- Sets appropriate ownership (`wazuh:wazuh`) and permissions (640)
- Maps certificate files to wazuh-manager expected names:
  - `wazuh-1-key.pem` → `manager-key.pem`
  - `wazuh-1.pem` → `manager.pem`
  - `root-ca.pem` → `root-ca.pem`
- Updates `ossec.conf` with indexer configuration

**Important:** Must be executed after installing wazuh-manager and before starting the service.

**VS Code Task:** Available as "E2E Scripts: Copy wazuh-manager certs" in the task menu (`Ctrl+Shift+P` → `Tasks: Run Task`)

### purge_wazuh.sh (e2e wrapper)
Alias to `scripts/purge_wazuh.sh` - provides a convenient cleanup utility from the e2e directory.

**VS Code Task:** Available as "Scripts: Purge wazuh-manager" in the task menu


## Additional Resources

- **VS Code Tasks**: Pre-configured build, test, and utility tasks are available in `.vscode/tasks.json`
- **Launch Configurations**: Debug configurations available in `.vscode/launch.json`
- **Engine Documentation**: See `wazuh/src/engine/docs/` for detailed engine architecture and API documentation
