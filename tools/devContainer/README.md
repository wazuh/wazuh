# Wazuh Manager Development Container

This development container provides a complete, ready-to-use environment for developing and testing the Wazuh Manager, covering all of its components (server, Engine, and framework). It includes all necessary tools, dependencies, and pre-configured VS Code settings to streamline the development workflow.

## Features

- **Complete Build Environment**: Includes all required dependencies to compile the Wazuh Manager from source — server, Engine and framework — (GCC, CMake, Python, Go, Docker CLI, and more)
- **IDE Integration**: Pre-configured VS Code settings, tasks, and launch configurations for debugging and development
- **Docker-in-Docker**: Full Docker support for running containerized services within the development environment
- **Development Tools**: Git, GitHub CLI, SSH server, and various development utilities pre-installed
- **Python & Go Support**: Configured Python and Go environments for extending Manager functionality

## Getting Started

### Supported platforms

- **Linux x64**
- **macOS ARM** (Apple silicon) with Docker Desktop

The devContainer runs a prebuilt image published for `amd64` and `arm64`, so each platform pulls its own architecture.

### Prerequisites

The following tools must be installed and running on your system before using the download script:

- **Docker**: Must be installed and the Docker daemon must be running (Docker Desktop on macOS)
- **Git**: Must be installed
- **A GitHub account with access to `ghcr.io/wazuh`**: the image is a private package, see [Logging in to ghcr.io](#logging-in-to-ghcrio)
- **GitHub CLI (`gh`)**: optional, one of the two ways to log in to `ghcr.io`
- **Node.js >= 20**: only to rebuild the image yourself, see [Working on the image](#working-on-the-image)

> [!NOTE]
> If your user is not in the `docker` group, the script will warn you and you may need `sudo` privileges. The warning is skipped on macOS.

### Logging in to ghcr.io

The devContainer image lives under `ghcr.io/wazuh`, and packages there are private. `ghcr.io` answers `denied` or `unauthorized` both for a private package and for one that does not exist, so a missing login and a missing tag look the same until you are logged in.

You do not need to log in beforehand: when the image is not accessible with your current Docker credentials, the script asks, and offers the same menu in both cases. To log in first, use any of the two ways below.

```
The devContainer image <IMAGE> is not accessible with your current Docker credentials.
Packages under <REGISTRY>/<OWNER> are private: you need a GitHub account with access to them.
How do you want to log in to <REGISTRY>?
  1) With the GitHub CLI (gh auth refresh -s read:packages, then docker login with its token)
  2) With a personal access token (classic) with the read:packages scope
  3) Exit
Choice:
```

The menu always shows the three options. When the GitHub CLI route is not available (`gh` is not installed, `gh auth status -h github.com` fails, `GH_TOKEN` or `GITHUB_TOKEN` is set, or the registry is not `ghcr.io`), the first line ends with ` (unavailable: gh is not installed or not logged in to github.com)`; choosing `1` then prints `option 1 is unavailable` and asks again; any other answer than `1`, `2` or `3` prints `Please answer 1, 2 or 3.`

**Option 1: GitHub CLI.** The script runs `gh auth refresh -h github.com -s read:packages`, reads your login with `gh api user -q .login`, and passes the token of `gh auth token` to `docker login` on stdin.

- `gh auth refresh` is interactive: it opens the browser and asks about git credentials.
- It creates a **new** token every time. The one stored earlier in Docker is revoked, so a second run of `gh auth refresh` invalidates the credential of the first.
- The token it stores is an OAuth token with the `repo` scope in addition to `read:packages`: broader than this needs.
- It does not work when `GH_TOKEN` or `GITHUB_TOKEN` is defined.

**Option 2: personal access token (classic).** `ghcr.io` only accepts a **classic** token. Create one with the `read:packages` scope and nothing else: it is the least privilege that works. The script asks for your GitHub user and the token, and passes the token to `docker login` on stdin. The token is never an argument of a command, nor written to a file or printed.

Manually, the equivalent is:

```bash
echo "$TOKEN" | docker login ghcr.io -u <github-user> --password-stdin
```

If your organization enforces SAML single sign-on, authorize the token for it in your GitHub token settings, or the registry keeps answering `denied`.

Docker stores the credential itself, not the script: in the credential helper named by `credHelpers["ghcr.io"]` or `credsStore` (Docker Desktop on macOS usually uses `credsStore: desktop`), or else in the `auths` entry of `${DOCKER_CONFIG:-$HOME/.docker}/config.json`. `docker logout ghcr.io` removes it.

### Quick Start

Download and set up the development container:

```bash
curl -o download_devContainer.sh https://raw.githubusercontent.com/wazuh/wazuh/5.0.0/tools/devContainer/download_devContainer.sh
chmod +x download_devContainer.sh
./download_devContainer.sh -h
```

**Options:**
- `-d <destination>`: Specify destination directory (default: `./devContainer`)
- `-b <branch>`: Specify Git branch to download from (default: `5.0.0`). The devContainer also clones this branch of the repository on creation. The branch must ship the prebuilt image (see [How the image is published](#how-the-image-is-published))
- `-c <claude.tar.gz>`: Copy a Claude Code setup exported with `claude-portable.sh export` into the destination and print the command that imports it once the devContainer is up
- `-h`: Show help message (covers the login, the pull and `WAZUH_DEVCONTAINER_IMAGE`)

**Example:**
```bash
./download_devContainer.sh -d ~/wazuh-manager-dev -b 5.0.0
```

> [!NOTE]
> The destination directory must not already exist — the script exits with an error if it does. It is only created after the image has been pulled; if the script fails, it does not leave a destination behind.

> [!NOTE]
> After the download completes, when the script runs in a terminal it asks whether you want to open the devContainer in VS Code. If VS Code and the Remote - Containers extension are available, it will open the workspace automatically; otherwise it will print a warning to open manually. Without a terminal it does not ask: it prints the `code --folder-uri …` command to run yourself.

> [!NOTE]
> Without a terminal the script cannot ask you to log in either: log in first ([Logging in to ghcr.io](#logging-in-to-ghcrio)) and run it again.

### What the script does

In order:

1. Checks the prerequisites.
2. Clones the branch given with `-b` into a temporary directory.
3. Checks the clone, **before touching Docker**: that `devcontainer.json` and `VERSION.json` exist, and that `devcontainer.json` has an `"image"` line. Older branches (`4.14.10` has no `.devcontainer/devcontainer.json`; `5.0.0` and `main` still carried the previous `devcontainer.json` until the one with the `"image"` line reaches them) stop here with an error.
4. Computes the image: the repository of the `"image"` line (or `$WAZUH_DEVCONTAINER_IMAGE`) plus the tag `<major>.<minor>` of `VERSION.json` (`5.0` for `5.0.0`).
5. Checks access to the registry with `docker manifest inspect`. If the image is not accessible, it offers the login menu once (only in a terminal) and tries again.
6. Pulls the image with `docker pull`.
7. Copies the configuration to the destination and patches the name, the branch and the `"image"` line of `devcontainer.json`.
8. Copies the Claude Code package, when `-c` is given.
9. Offers to open the workspace in VS Code.

When the image is ready, it prints `The devContainer image <IMAGE> is ready.` before the download message.

### What gets downloaded

The script downloads only the core devContainer configuration:

```
<destination>/
├── .devcontainer/          # Dockerfile, devcontainer.json, image.devcontainer.json, build-image.sh, fix-dind.sh, reinstall-cmake.sh, reinstall-clang-format.sh
├── .vscode/                # VS Code tasks, launch, and settings
└── claude-portable.tar.gz  # only with -c
```

`devcontainer.json` is what VS Code opens: it names the prebuilt image. `image.devcontainer.json`, the Dockerfile and `build-image.sh` are the recipe to rebuild that image (see [Working on the image](#working-on-the-image)).

The `scripts/` and `e2e/` directories are **not** included in the download. They are available in the full Wazuh repository under `tools/devContainer/`.

### First start

On the first start ("Reopen in Container" or `devcontainer up`), the devContainer runs the image the script already pulled: there is no image build. If the image were not in the local Docker, VS Code would pull it, several GB, which is what the script did beforehand so that a missing login shows up before the destination is created. Then `postCreateCommand` runs two steps in sequence:

1. `.devcontainer/fix-dind.sh`: Docker-in-Docker on the nftables backend with the cgroupfs driver; it waits until dockerd answers.
2. The clone of the repository, on the branch given with `-b`, submodules included, into `wazuh.partial/`. It is renamed to
   `wazuh/` (`$WAZUH_REPO`) only once the clone has completed:
   - an existing `wazuh/` checkout is kept, and its submodules are updated;
   - a non-empty `wazuh/` that is not a git checkout is left untouched, and the step fails.

Then `postStartCommand` sets `vm.max_map_count`, which the indexer needs, and `fs.inotify.max_user_watches`, and prints which image the container runs (`devContainer image: ci` for the published one, `local` for one built with `build-image.sh`). If either step fails, the creation log shows a failed `postCreateCommand`, and the devContainer skips `postStartCommand`.

### Updating the image

The image tag (`5.0`) is rebuilt when the recipe changes, so the image you pulled can get old. To update it:

```bash
docker pull ghcr.io/wazuh/wazuh-devcontainer:5.0
```

then run **Dev Containers: Rebuild Container** in VS Code. Use the repository and tag of the `"image"` line in your `devcontainer.json`.

> [!NOTE]
> **Rebuild Without Cache** does not pull the image; run `docker pull` first.

### Working on the image

To change the image (the Dockerfile, the `*.sh` it copies, or the features in `image.devcontainer.json`), build it locally from the `.devcontainer/` folder; this needs Node.js >= 20 (or the `devcontainer` CLI) and Docker:

```bash
.devcontainer/build-image.sh
```

The script builds for your host's platform with the devcontainer CLI and leaves `<repository>:<tag>` of the `"image"` line of `devcontainer.json` in your local Docker. Then run **Dev Containers: Rebuild Container**: the container uses your image, and the startup line says `devContainer image: local`. Options: `--platform`, `--image`, `--tag` (see `build-image.sh --help`).

To go back to the published image, pull it again (`docker pull ghcr.io/wazuh/wazuh-devcontainer:5.0`) and rebuild the container.

> [!NOTE]
> Without a login to `ghcr.io`, the local build may print an `ERROR … cache importer` line: it tries to use the published image as a layer cache. It is not fatal; the build continues without the cache.

On a fork, point both the download script and `build-image.sh` to your own registry with `WAZUH_DEVCONTAINER_IMAGE`, the image repository without a tag:

```bash
WAZUH_DEVCONTAINER_IMAGE=ghcr.io/<owner>/wazuh-devcontainer ./download_devContainer.sh -b <branch>
WAZUH_DEVCONTAINER_IMAGE=ghcr.io/<owner>/wazuh-devcontainer .devcontainer/build-image.sh --tag 5.0
```

### How the image is published

> [!NOTE]
> Provisional: this section describes the workflow as designed and is reconciled with the final one afterwards.

The workflow `.github/workflows/5_builderprecompiled_devcontainer-image.yml` builds `ghcr.io/wazuh/wazuh-devcontainer` with `build-image.sh`, for `amd64` and `arm64`, and publishes a single multi-platform tag, `<major>.<minor>` of `VERSION.json` (`5.0` today). It runs:

- on a push to `5.x.y` branches or `main` that changes `tools/devContainer/.devcontainer/**` or the workflow itself;
- on demand, with `workflow_dispatch`, which only re-runs the build for a branch that already has the right configuration.

The workflow fails if the tag in the `"image"` line of `.devcontainer/devcontainer.json` is not the `<major>.<minor>` of `VERSION.json`. For that reason, a new release line (for example `5.1.0`, and `main` after the forward-merge) first needs a commit that bumps the tag of the `"image"` line to the new `<major>.<minor>`. That commit touches `.devcontainer/**`, so it is what triggers the build. Launching `workflow_dispatch` alone does not work around it.

After each run, a cleanup step deletes the untagged versions of the package that are no longer in use. Deleted versions can be restored for 30 days.

### Troubleshooting

**`denied` or `unauthorized` when pulling or inspecting the image.** You are not logged in to `ghcr.io`, or your account has no access to the package. Log in as described in [Logging in to ghcr.io](#logging-in-to-ghcrio); if your organization enforces SSO, authorize the token for it. Without a stored credential the script offers the login menu (in a terminal); when Docker already has a credential for the registry and access is still denied, it reports:

```
Error: <IMAGE> is still not accessible with the credentials stored for <REGISTRY>: the tag is not published for this branch, or your account has no access to the package. If the stored credential is old, run 'docker logout <REGISTRY>' and try again (README: "Troubleshooting").
```

**An old or revoked credential.** The script does not offer the login again when Docker already has a credential for `ghcr.io`. Remove it and run the script again:

```bash
docker logout ghcr.io
```

This also happens after `gh auth refresh`, which revokes the token stored earlier.

**`manifest unknown`.** The registry answers, but the tag does not exist: the image is not published for that branch. The script says `<IMAGE> is not published (manifest unknown)`. See [How the image is published](#how-the-image-is-published).

**`branch '<B>' predates the prebuilt devContainer image`.** The branch given with `-b` has no `"image"` line in its `devcontainer.json`. Pick a branch that ships it.

**`Docker is configured to use the credential helper 'docker-credential-<H>', which is not in PATH.`** The helper named in your Docker configuration is not installed or not in `PATH`, so Docker cannot read its credentials. Install it or fix `PATH`; until then the script treats the registry as having no credential and offers the login menu (in a terminal).

**`cannot reach <REGISTRY>`.** Docker could not contact the registry (the message continues with the first line of the Docker error): check the network and the Docker daemon.

**`... is not accessible and there is no terminal to log in`.** The script cannot ask without a terminal. Log in first and run it again.

### Importing a Claude Code setup (`-c`)

`-c <claude.tar.gz>` only copies the package into the destination folder; nothing imports it automatically. Once the
devContainer is up and `wazuh/` has been cloned, run this from the workspace folder inside it:

```bash
tar xzf claude-portable.tar.gz -C /tmp claude/skills/claude-portable/scripts/claude-portable.sh
bash /tmp/claude/skills/claude-portable/scripts/claude-portable.sh import claude-portable.tar.gz
bash .claude/skills/claude-portable/scripts/claude-portable.sh doctor --fetch
```

The first command extracts only the import script. `import` then does four things:

1. It checks every file against the package manifest (sha256). On any mismatch it installs nothing.
2. It creates `.claude/` with the paths of this workspace.
3. If the package carries the project memory, it installs it under `~/.claude/projects/<workspace slug>/memory/`
   without overwriting existing files. Differing files are listed as conflicts, to merge by hand.
4. It ends with `doctor`.

`doctor --fetch` offers to fetch what the skills need outside the repository (`qa-integration-framework`, `qa-venv`,
the Codex plugin), and asks before each download or install.

Start Claude Code from the workspace folder so it picks up `.claude/` and the memory. If it was already running, restart it.

To produce the package, run `claude-portable.sh export --with-memory` in an existing devContainer. The package never
contains `settings.local.json`, and the export refuses to pack credentials.

### Build tree

There is **one** CMake tree, `$WAZUH_REPO/src/build`: `make TARGET=manager` configures it, and the VS Code CMake Tools
extension builds in the same tree (`cmake.buildDirectory`, with the same `Unix Makefiles` generator and
`TARGET=manager`). `ENGINE_BUILD` is its `engine/` subdirectory, where the engine binary (`wazuh-engine`) and the
engine unit tests (`source/<module>/<module>_utest`) land — the paths `launch.json` and TestMate use, and the binary
the installer copies. CMake Tools does not configure on open (`cmake.configureOnOpen: false`), so opening VS Code
never changes the tree's build type; configure it with `make` (or the CMake Tools *Configure* command) and build targets
from the tree root:

```bash
cmake --build $WAZUH_REPO/src/build -j"$(nproc)" --target wazuh-engine
```


## Development Utilities (scripts/)

> [!NOTE]
> The `scripts/` directory is not downloaded by `download_devContainer.sh`. It is available in the Wazuh repository at `tools/devContainer/scripts/`.

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
> The `e2e/` directory is not downloaded by `download_devContainer.sh`. It is available in the Wazuh repository at `tools/devContainer/e2e/`.

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

Each service mounts a persistent volume for `/var/ossec`. There is no restart policy: like the indexer and the dashboard, the agents stay stopped when the devContainer restarts, and `docker compose start` brings them back with their keys once the manager is running. Use `docker-compose down -v` for a clean start that discards agent state.

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
