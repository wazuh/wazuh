# Wazuh server embedded Python Builder Script

`generate-cpython.sh` builds the **embedded CPython for the Wazuh manager and/or its Python dependencies** inside a
preconfigured Docker container. In CI, the `cpython` job of `5_builderpackage_externals.yml` runs `compile.sh` against
the dependency pool tree of the same run.

It detects the host architecture, pulls the matching builder image from **GitHub Container Registry (GHCR)**, and runs
`compile.sh` inside the container.

## Main Features

- Detects the host architecture (`x86_64`/`amd64` or `aarch64`/`arm64`)
- Reads the Wazuh version from `VERSION.json` (`.version`)
- Pulls `ghcr.io/wazuh/pkg_rpm_manager_builder_amd64:<version>` or `ghcr.io/wazuh/pkg_rpm_manager_builder_arm64:<version>`
- Runs `compile.sh` inside the container, with the repository mounted at `/wazuh_host`
- Exports the generated artifacts to the `./output` directory

## Requirements

### Required software

- bash
- docker
- jq

The container is started with `docker run -it`, so the script must be run from an interactive terminal.

### Required environment variables

The following variables must be defined **before running the script**, either in the environment or in a
`config.env` file in the current directory:

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
| `WAZUH_BRANCH`  | `<branch>`     | Branch to clone from GitHub inside the container instead of copying the local repository. When unset, the local repository is copied and left unmodified. |
| `BUILD_CPYTHON` | `true/false`   | Builds CPython from the sources of the version in `framework/.python-version`, with the module setup in `custom/`. Default `false`. |
| `BUILD_DEPS`    | `true/false`   | Downloads the wheels in `framework/requirements.txt`. Default `false`; also done whenever `BUILD_CPYTHON=true`. |

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

1. Validate the required environment variables
2. Detect the host architecture
3. Log in to GitHub Container Registry
4. Pull the builder image
5. Run the compilation (`make deps`, the optional CPython build and wheel download, then an install of the
   interpreter and its dependencies under `/var/wazuh-manager` inside the container)
6. Store the generated artifacts in `./output`

---

## Output

All build artifacts are written to `./output/` with the following naming convention:

- CPython source and build tree (`src/external/cpython`): `cpython_x86_64.tar.gz` or `cpython_arm64.tar.gz`
- Ready-to-use interpreter with its dependencies (`/var/wazuh-manager/framework/python`): `cpython.tar.gz`

## Common Errors

- **Unsupported architecture**
  The script exits with `Unsupported architecture (<arch>)` if `uname -m` is not `amd64`/`x86_64` or `arm64`/`aarch64`.

- **Missing credentials**
  If `GITHUB_USER` or `GHCR_TOKEN` is not set, the script lists the missing variables and exits.
