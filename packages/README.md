## Wazuh Package Builder Script

This script automates the process of building Wazuh packages (manager or agent) for various architectures within a Docker container.

**Features:**

- Supports building packages for different targets (manager/agent).
- Selectable architectures (amd64, i386, **ppc64le, arm64, armhf*).
- Optional debug builds.
- Generates checksums for built packages.
- Builds legacy packages for CentOS 5 (RPM only).
- Uses local source code or downloads from GitHub.
- Builds future test packages (x.30.0).

***Note:** Support for *ppc64le, arm64, and armhf* architectures **is not** currently **available** in the **workflow**.

**Requirements:**

- Docker installed and running.

**Usage:**
```
wazuh# cd packages
./generate_package.sh [OPTIONS]
```

**Options:**
| Option     | Description                                            | Default               |
|------------|----------------------------------------------------------|-----------------------|
| -b, --branch | Git branch to use (optional)                          | main                |
| -t, --target | Target package to build (required): manager or agent    | -                     |
| -a, --architecture | Target architecture (optional): amd64, i386, etc. | -                     |
| -j, --jobs  | Number of parallel jobs (optional)                       | 2                     |
| -r, --revision | Package revision (optional)                          | 0                     |
| -s, --store  | Destination path for the package (optional)            | (output folder created) |
| -p, --path   | Installation path for the package (optional)           | /var/ossec             |
| -d, --debug  | Build binaries with debug symbols (optional)           | no                     |
| -c, --checksum | Generate checksum on the same directory (optional)   | no                     |
| -l, --legacy | Build package for CentOS 5 (RPM only) (optional)        | no                     |
| --dont-build-docker | Use a locally built Docker image (optional)      | no   |
| --tag        | Tag to use with the Docker image (optional)             | -                     |
| *--sources    | Path containing local Wazuh source code (optional)       | script path            |
| **--is_stage | Use release name in package (optional)               | no                     |
| --src        | Generate the source package (optional)                 | no                     |
| --system | Package format to build (optional): rpm, deb (default)| deb                    |
| -h, --help   | Show this help message                                 | -                     |

***Note1:** If we don't use this flag, will the script use the current directory where *generate_package.sh* is located.

****Note 2:** If the package is not a release package, a short hash commit based on the git command `git rev-parse --short HEAD` will be appended to the end of the name. The default length of the short hash is determined by the Git command [git rev-parse --short[=length]](https://git-scm.com/docs/git-rev-parse#Documentation/git-rev-parse.txt---shortlength:~:text=interpreted%20as%20usual.-,%2D%2Dshort%5B%3Dlength%5D,-Same%20as%20%2D%2Dverify).


**Example Usage:**

1. Build a manager package for amd64 architecture:
./wazuh_package_builder.sh -t manager -a amd64 -s /tmp --system rpm

2. Build a debug agent package for i386 architecture with checksum generation:
./wazuh_package_builder.sh -t agent -a i386 -s /tmp -d -c --system rpm

3. Build a legacy RPM package for CentOS 5 (agent):
./wazuh_package_builder.sh -t agent -l -s /tmp --system rpm

4. Build a package using local Wazuh source code:
./wazuh_package_builder.sh -t manager -a amd64 --sources /path/to/wazuh/source --system rpm


**Notes:**
- For `--dont-build-docker` to work effectively, ensure a Docker image with the necessary build environment is already available.
- For RPM packages, we use the following architecture equivalences:
    * amd64 -> x86_64
    * arm64 -> aarch64
    * armhf -> armv7hl

# Workflow

## Generate and push builder images to GH

```bash
curl -L -X POST -H "Accept: application/vnd.github+json" -H "Authorization: Bearer $GH_WORKFLOW_TOKEN" -H "X-GitHub-Api-Version: 2022-11-28" --data-binary "@$(pwd)/wazuh-agent-test-amd64-rpm.json" "https://api.github.com/repos/wazuh/wazuh/actions/workflows/packages-upload-agent-images-amd.yml/dispatches"
```

Where the JSON looks like this:

```json
# cat wazuh-agent-test-amd64-rpm.json
{
    "ref":"4.9.0",
    "inputs":
        {
         "tag":"auto",
         "architecture":"amd64",
         "system":"rpm",
         "revision":"test",
         "is_stage":"false",
         "legacy":"false"
        }
}
```

## Generate packages

```json
curl -L -X POST -H "Accept: application/vnd.github+json" -H "Authorization: Bearer $GH_WORKFLOW_TOKEN" -H "X-GitHub-Api-Version: 2022-11-28" --data-binary "@$(pwd)/wazuh-agent-test-amd64-rpm.json" "https://api.github.com/repos/wazuh/wazuh/actions/workflows/packages-build-linux-agent-amd.yml/dispatches"
```

Where the JSON looks like this:
```json
# cat wazuh-agent-test-amd64-rpm.json
{
    "ref":"4.9.0",
    "inputs":
        {
         "docker_image_tag":"auto",
         "architecture":"amd64",
         "system":"deb",
         "revision":"test",
         "is_stage":"false",
         "legacy":"false",
         "checksum":"false",
     }
}
```

