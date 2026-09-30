## Wazuh Package Builder Script

This script automates the process of building Wazuh packages (manager or agent) for various architectures within a Docker container.

**Features:**

- Supports building packages for different targets (manager/agent).
- Selectable architectures (amd64, arm64).
- Optional debug builds.
- Generates checksums for built packages.
- Uses local source code or downloads from GitHub.
- Builds future test packages (x.30.0).

***Note:** Only *amd64* and *arm64* architectures are supported.

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
| -b, --branch         | Git branch to use (optional)                                        | (none: mounts the local checkout) |
| -t, --target         | Target package to build (required): manager or agent                | -                       |
| -a, --architecture   | Target architecture (optional): amd64, arm64                        | -                       |
| -j, --jobs           | Number of parallel jobs (optional)                                  | 2                       |
| -r, --revision       | Package revision (optional)                                         | 0                       |
| -s, --store          | Destination path for the package (optional)                         | (output folder created) |
| -p, --path           | Installation path for the package (optional)                        | /var/wazuh-manager (manager), /var/ossec (agent) |
| -d, --debug          | Build binaries with debug symbols (optional)                        | no                      |
| -c, --checksum       | Generate checksum on the same directory (optional)                  | no                      |
| --dont-build-docker  | Use a locally built Docker image (optional)                         | no                      |
| --tag                | Tag to use with the Docker image (optional)                         | -                       |
| *--sources           | Path containing local Wazuh source code (optional)                  | script path             |
| **--is_stage         | Use release name in package (optional)                              | no                      |
| --src                | Generate the source package (optional)                              | no                      |
| --system             | Package format to build (optional): rpm, deb (default)              | deb                     |
| -h, --help           | Show this help message                                              | -                       |

***Note1:** If we don't use this flag, will the script use the current directory where *generate_package.sh* is located.

****Note 2:** If the package is not a release package, a short hash commit based on the git command `git rev-parse --short HEAD` will be appended to the end of the name. The default length of the short hash is determined by the Git command [git rev-parse --short[=length]](https://git-scm.com/docs/git-rev-parse#Documentation/git-rev-parse.txt---shortlength:~:text=interpreted%20as%20usual.-,%2D%2Dshort%5B%3Dlength%5D,-Same%20as%20%2D%2Dverify).


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

# Workflow

## Generate and push builder images to GH

```bash
curl -L -X POST -H "Accept: application/vnd.github+json" -H "Authorization: Bearer $GH_WORKFLOW_TOKEN" -H "X-GitHub-Api-Version: 2022-11-28" --data-binary "@$(pwd)/wazuh-agent-test-amd64-rpm.json" "https://api.github.com/repos/wazuh/wazuh/actions/workflows/packages-upload-agent-images-amd.yml/dispatches"
```

Where `wazuh-agent-test-amd64-rpm.json` looks like this:

```json
{
    "ref":"5.0.0",
    "inputs":
        {
         "tag":"auto",
         "architecture":"amd64",
         "system":"rpm",
         "revision":"test",
         "is_stage":"false"
        }
}
```

## Generate packages

```bash
curl -L -X POST -H "Accept: application/vnd.github+json" -H "Authorization: Bearer $GH_WORKFLOW_TOKEN" -H "X-GitHub-Api-Version: 2022-11-28" --data-binary "@$(pwd)/wazuh-agent-test-amd64-rpm.json" "https://api.github.com/repos/wazuh/wazuh/actions/workflows/packages-build-linux-agent-amd.yml/dispatches"
```

Where `wazuh-agent-test-amd64-rpm.json` looks like this:

```json
{
    "ref":"5.0.0",
    "inputs":
        {
         "docker_image_tag":"auto",
         "architecture":"amd64",
         "system":"deb",
         "revision":"test",
         "is_stage":"false",
         "checksum":"false"
        }
}
```
