# Wazuh server embedded Python Builder Script

This Bash script is used to **build Embedded CPython and/or its dependencies for Wazuh** using a preconfigured Docker container.

It automatically detects the host architecture, pulls the correct image from **GitHub Container Registry (GHCR)**, and runs the compilation process inside the container.

## Main Features

- Automatically detects the host architecture (`amd64` / `arm64`)
- Reads the Wazuh version from `VERSION.json`
- Pulls the appropriate Docker image for the detected architecture and version
- Runs the `compile.sh` build script inside the container
- Exports generated artifacts to the `./output` directory

## Requirements

### Required software

- bash
- docker
- jq

### Required environment variables

The following variables must be defined **before running the script**, either in the environment or in a `config.env` file:

- `GITHUB_USER` – GitHub username
- `GHCR_TOKEN` – GitHub token with permission to pull images from GHCR

Example `config.env` file:

```bash
GITHUB_USER=my-github-user
GHCR_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
```

---

## Optional Configuration Variables

| Variable        | Value          | Description |
|-----------------|----------------|-------------|
| `WAZUH_BRANCH`  | `<branch>`     | Wazuh branch to use during the build. Optional to not use local code. |
| `BUILD_CPYTHON` | `true/false`   | Enables CPython build |
| `BUILD_DEPS`    | `true/false`   | Enables dependency build |

Example:

```bash
WAZUH_BRANCH=enhancement/my-branch
BUILD_CPYTHON=true
BUILD_DEPS=true
```

---

## Usage

From the directory where the script is located:

```bash
BUILD_CPYTHON=[true/false] BUILD_DEPS=[true/false] WAZUH_BRANCH=[wazuh-branch] ./generate-cpython.sh
```

The script will:

1. Validate required environment variables
2. Detect the host architecture
3. Log in to GitHub Container Registry
4. Pull the appropriate Docker image
5. Run the compilation process
6. Store the generated artifacts in `./output`

---

## Output

All build artifacts are written to `./output/` with the following naming convension:

- Sources: `cpython_[amd64/x86_64].tar.gz`
- Compiled: `cpython.tar.gz`


## Common Errors

- **Unsupported architecture**
  The script exits if `uname -m` is not `amd64/x86_64` or `arm64/aarch64`

- **Missing credentials**
  If `GITHUB_USER` or `GHCR_TOKEN` are not set, the script exits immediately
