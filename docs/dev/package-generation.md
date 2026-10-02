# Package generation

## Wazuh Package Builder Script

`packages/generate_package.sh` builds a manager or agent `.deb`/`.rpm` inside a Docker builder image (`pkg_<system>_<target>_builder_<arch>`).

**Features:**

- Supports building packages for different targets (manager/agent).
- Selectable architectures (amd64, arm64); any other value is refused.
- Optional debug builds.
- Generates checksums for built packages.
- Uses the local checkout, another local source tree, or a branch downloaded from GitHub.

**Requirements:**

- Docker installed and running.

**Usage:**
```
wazuh# cd packages
./generate_package.sh [OPTIONS]
```

**Options:**

| Option               | Description                                                         | Default                 |
|----------------------|---------------------------------------------------------------------|-------------------------|
| -b, --branch         | Git branch to download and build                                    | (none: mounts the local checkout) |
| -t, --target         | Target package to build: manager or agent                           | agent                   |
| -a, --architecture   | Target architecture: amd64, arm64                                   | amd64                   |
| -j, --jobs           | Number of parallel jobs                                             | 2                       |
| -r, --revision       | Package revision                                                    | 0                       |
| -s, --store          | Destination path for the package                                    | (output folder created) |
| -p, --path           | Installation path for the package                                   | /var/wazuh-manager (manager), /var/ossec (agent) |
| -d, --debug          | Build binaries with debug flags (without optimizations)             | no                      |
| -c, --checksum       | Generate checksum on the same directory                             | no                      |
| --dont-build-docker  | Use a locally built Docker image instead of building it             | no                      |
| --tag                | Tag to use with the Docker image                                    | -                       |
| --sources            | Absolute path containing the Wazuh source code to mount             | the checkout `generate_package.sh` belongs to |
| --is_stage           | Use the release name in the package (no commit hash)                | no                      |
| --src                | Also generate the source package                                    | no                      |
| --system             | Package format: rpm, deb                                            | deb                     |
| --future             | Build a test package versioned x.30.0, for development purposes           | no                      |
| --verbose            | Print commands and their arguments as they run                      | no                      |
| --force              | Allow a manager package with `-p /var/ossec`, refused otherwise     | no                      |
| -h, --help           | Show this help message                                              | -                       |

Without `--is_stage`, the 7-character commit hash (`git rev-parse --short=7 HEAD` of the mounted sources, or the GitHub commit of `-b`) is appended to the package name.

**Example Usage:**

1. Build a manager package for amd64 architecture:
`./generate_package.sh -t manager -a amd64 -s /tmp --system rpm`

2. Build a debug agent package for arm64 architecture with checksum generation:
`./generate_package.sh -t agent -a arm64 -s /tmp -d -c --system rpm`

3. Build a package using local Wazuh source code:
`./generate_package.sh -t manager -a amd64 --sources /path/to/wazuh/source --system rpm`


**Notes:**
- For `--dont-build-docker` to work effectively, ensure a Docker image with the necessary build environment is already available.
- For RPM packages, we use the following architecture equivalences:
    * amd64 -> x86_64
    * arm64 -> aarch64

## Windows Agent Package

`packages/windows/generate_compiled_windows_agent.sh` compiles the Windows agent in a Docker container and packs the build tree into a zip, which `generate_wazuh_msi.ps1` then turns into the MSI on a Windows host.

**Usage:**
```
wazuh# cd packages/windows
./generate_compiled_windows_agent.sh -o <name>.zip [OPTIONS]
```

**Options:**

| Option                    | Description                                                         | Default                                                          |
|---------------------------|---------------------------------------------------------------------|------------------------------------------------------------------|
| -o, --output              | Name of the output zip (required)                                   | -                                                                |
| -b, --branch              | Git branch to compile (optional)                                    | -                                                                |
| --sources                 | Path containing local Wazuh source code (optional)                  | ../../src                                                        |
| -j, --jobs                | Number of parallel jobs (optional)                                  | 4                                                                |
| -s, --store               | Destination path for the zip (optional)                             | current path                                                     |
| -d, --debug               | Build binaries with debug symbols (optional)                        | no                                                               |
| -t, --trust_verification  | Module signature verification: 0, 1 or 2 (optional)                 | 1                                                                |
| -c, --ca_name             | Root CA required by the module signature verification (optional)    | Microsoft Identity Verification Root Certificate Authority 2020 |
| --dont-build-docker       | Use a locally built Docker image (optional)                         | no                                                               |
| --tag                     | Tag to use with the Docker image (optional)                         | -                                                                |

**Module signature verification (`-t`, `-c`):**

At startup, `wazuh-agent.exe`, `win32ui.exe`, `manage_agents.exe` and `active-response\bin\block-ip.exe` verify the signature of every module they load (Authenticode, or the system catalog for Windows files), after checking that the `-c` root is in the Windows `ROOT` store. If the root is not there, the agent verifies its own signature first, which lets Windows install the root when it is trusted, and checks again.

- `-t 0`: disabled.
- `-t 1`: a failed check or an unverified module is logged as a warning. If the root check fails, no module is verified. Released packages use this mode.
- `-t 2`: a failed check or an unverified module stops the process.

`-c` must be the root the packages are signed under: `Microsoft Identity Verification Root Certificate Authority 2020` for Azure Artifact Signing. Endpoints that cannot install that root are covered in [Installation](../ref/getting-started/installation.md#module-signature-verification).

## CI workflows

The builder images and the packages are also produced by GitHub Actions workflows.

**Builder images.** `5_builderprecompiled_docker-images-upload.yml` rebuilds and pushes the images whose files changed on every push under `packages/` to a `5.x.y` or `main` branch. The manager images can also be pushed on demand:

```bash
gh workflow run 5_builderprecompiled_docker-images-upload-manager.yml --ref <branch> \
  -f architecture=amd64 -f system=deb -f source_reference=<branch> -f docker_image_tag=auto
```

`docker_image_tag` is `auto` (the version in `VERSION.json`), `developer` (the branch name) or a literal tag.

**Packages.** `5_builderpackage_manager.yml` builds the manager package and `5_builderpackage_agent-linux.yml` the Linux agent package:

```bash
gh workflow run 5_builderpackage_manager.yml --ref <branch> \
  -f architecture=amd64 -f system=deb -f revision=0 -f docker_image_tag=auto
gh workflow run 5_builderpackage_agent-linux.yml --ref <branch> \
  -f architecture=amd64 -f system=rpm -f revision=0
```

The manager workflow also takes `is_stage`, `debug`, `checksum`, `upload_package` (default `true`) and `id`; the agent one takes `debug` and `checksum`.
