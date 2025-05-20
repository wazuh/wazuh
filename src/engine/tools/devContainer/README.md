# Engine Development Container

This container is used to develop the Wazuh engine.

## Features

- Includes all necessary dependencies to compile the Wazuh engine from source.
- The Wazuh engine is installed in the container at creation time.
- Pre-configured VS Code settings, tasks, and launch configurations are included to simplify development.

## Usage

To build the development container from scratch, run the following commands:

```bash
curl -o download_devContainer.sh https://raw.githubusercontent.com/wazuh/wazuh/main/src/engine/tools/devContainer/download_devContainer.sh
chmod +x download_devContainer.sh
./download_devContainer.sh -h
```

> [!NOTE]
> Only works on Linux.


## E2E environment: Wazuh-indexer + Wazuh-dashboard

The `e2e` folder contains scripts to launch a complete Wazuh environment within the devContainer. These scripts are
intended for testing and development.


### e2e/init.sh
- Creates certificates for the Wazuh API, wazuh-indexer, and Wazuh dashboard.
- Locates and downloads the latest artifacts for Wazuh Indexer (`wazuh-indexer-command-manager-5.0` and `wazuh-indexer-setup-5.0`) and Wazuh Dashboard (`wazuh-dashboard_5.0.0-latest_amd64.deb`). Always download from the GHA
  artifacts run on `main` branch.
- Helps bootstrap the Docker-based environment.

### e2e/docker-compose.yml
Brings up the following containers:
- **wazuh-indexer** exposed on port `9200` (HTTPS).
- **wazuh-dashboard** exposed on port `4040` (HTTPS).

### wazuh_copy_certs.sh
Copies generated certificates into an existing wazuh-server installation.
- Must be run after installing wazuh-server.
- Changes ownership of the certificates to `wazuh-server` user and appends extra configuration to wazuh-server.yml.
- This script is also a task in `.vscode/tasks.json` and can be executed from the task menu (`Ctrl+Shift+P` ->
`Tasks: Run Task` -> `Wazuh-server copy certs`).

### wazuh_purge.sh
Uninstalls `wazuh-server` and removes its files, directories, and associated user/group.
- Cleans up any residual paths left by the Wazuh server package.
- This script is also a task in `.vscode/tasks.json` and can be executed from the task menu (`Ctrl+Shift+P` ->
`Tasks: Run Task` -> `Wazuh-server clean`).

These scripts simplify the process of setting up, configuring, and tearing down a local Wazuh ecosystem for diagnosis or development.
