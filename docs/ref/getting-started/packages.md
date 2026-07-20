# Packages

This page lists the supported operating systems and architectures for Wazuh Server and Agent packages. Before installing Wazuh, verify that your platform and architecture are compatible with the available packages.

## Server

### Amazon Linux

| Platform     | Version | x86_64 | aarch64 |
| ------------ | ------- | :----: | :-----: |
| Amazon Linux | 2023    |   ✔️    |    ✔️    |
| Amazon Linux | 2       |   ✔️    |    ✔️    |

### Ubuntu

| Platform | Version | x86_64 | aarch64 |
| -------- | ------- | :----: | :-----: |
| Ubuntu   | 24.04   |   ✔️    |    ✔️    |
| Ubuntu   | 22.04   |   ✔️    |    ✔️    |

### Red Hat

| Platform | Version | x86_64 | aarch64 |
| -------- | ------- | :----: | :-----: |
| Red Hat  | 10      |   ✔️    |    ✔️    |
| Red Hat  | 9       |   ✔️    |    ✔️    |

## Agent

### Amazon Linux

| Platform     | Version | x86_64 | aarch64 |
| ------------ | ------- | :----: | :-----: |
| Amazon Linux | 2023    |   ✔️    |    ✔️    |
| Amazon Linux | 2       |   ✔️    |    ✔️    |
| Amazon Linux | 1       |   ✔️    |    ✔️    |

### Ubuntu

| Platform | Version | x86_64 | aarch64 |
| -------- | ------- | :----: | :-----: |
| Ubuntu   | 24.04   |   ✔️    |    ✔️    |
| Ubuntu   | 22.04   |   ✔️    |    ✔️    |
| Ubuntu   | 20.04   |   ✔️    |    ✔️    |
| Ubuntu   | 18.04   |   ✔️    |    ✔️    |

### Windows

| Platform       | Version | x86_64 | aarch64 |
| -------------- | ------- | :----: | :-----: |
| Windows        | 11      |   ✔️    |    ✔️    |
| Windows        | 10      |   ✔️    |    ✔️    |
| Windows Server | 2025    |   ✔️    |         |
| Windows Server | 2022    |   ✔️    |         |
| Windows Server | 2019    |   ✔️    |         |
| Windows Server | 2016    |   ✔️    |         |
| Windows Server | 2012 R2 |   ✔️    |         |
| Windows Server | 2008 R2 |   ✔️    |         |

### macOS

| Platform | Version | x86_64 | aarch64 |
| -------- | ------- | :----: | :-----: |
| macOS    | 15      |   ✔️    |    ✔️    |
| macOS    | 14      |   ✔️    |    ✔️    |

### Red Hat

| Platform | Version | x86_64 | aarch64 |
| -------- | ------- | :----: | :-----: |
| Red Hat  | 10      |   ✔️    |    ✔️    |
| Red Hat  | 9       |   ✔️    |    ✔️    |
| Red Hat  | 8       |   ✔️    |    ✔️    |
| Red Hat  | 7       |   ✔️    |    ✔️    |
| Red Hat  | 6       |   ✔️    |         |

### CentOS

| Platform      | Version | x86_64 | aarch64 |
| ------------- | ------- | :----: | :-----: |
| CentOS Stream | 10      |   ✔️    |    ✔️    |
| CentOS Stream | 9       |   ✔️    |    ✔️    |
| CentOS Stream | 8       |   ✔️    |    ✔️    |
| CentOS        | 8       |   ✔️    |    ✔️    |
| CentOS        | 7       |   ✔️    |    ✔️    |
| CentOS        | 6       |   ✔️    |         |

### Oracle Linux

| Platform     | Version | x86_64 | aarch64 |
| ------------ | ------- | :----: | :-----: |
| Oracle Linux | 9       |   ✔️    |    ✔️    |
| Oracle Linux | 8       |   ✔️    |    ✔️    |
| Oracle Linux | 7       |   ✔️    |         |
| Oracle Linux | 6       |   ✔️    |         |

### Debian

| Platform | Version | x86_64 | aarch64 |
| -------- | ------- | :----: | :-----: |
| Debian   | 13      |   ✔️    |    ✔️    |
| Debian   | 12      |   ✔️    |    ✔️    |
| Debian   | 11      |   ✔️    |    ✔️    |
| Debian   | 10      |   ✔️    |    ✔️    |
| Debian   | 9       |   ✔️    |         |
| Debian   | 8       |   ✔️    |         |
| Debian   | 7       |   ✔️    |         |

### Fedora

| Platform | Version | x86_64 | aarch64 |
| -------- | ------- | :----: | :-----: |
| Fedora   | 42      |   ✔️    |    ✔️    |
| Fedora   | 41      |   ✔️    |    ✔️    |

### SUSE

| Platform      | Version | x86_64 | aarch64 |
| ------------- | ------- | :----: | :-----: |
| OpenSUSE Leap | 15      |   ✔️    |    ✔️    |
| SLES          | 15      |   ✔️    |    ✔️    |

### AlmaLinux

| Platform  | Version | x86_64 | aarch64 |
| --------- | ------- | :----: | :-----: |
| AlmaLinux | 10      |   ✔️    |    ✔️    |
| AlmaLinux | 9       |   ✔️    |    ✔️    |
| AlmaLinux | 8       |   ✔️    |    ✔️    |

### Rocky Linux

| Platform    | Version | x86_64 | aarch64 |
| ----------- | ------- | :----: | :-----: |
| Rocky Linux | 10      |   ✔️    |    ✔️    |
| Rocky Linux | 9       |   ✔️    |    ✔️    |
| Rocky Linux | 8       |   ✔️    |    ✔️    |

---

## Package Download

Wazuh packages are available in different repositories depending on the release stage. Package paths follow this structure:

```
<BASE_URL>/<PACKAGE_TYPE>/<COMPONENT>_<VERSION>[-<REVISION>]_<ARCH>.<EXT>
```

### Repository URLs

| Environment        | Base URL                                                                  | Access         | Version format      |
| ------------------ | ------------------------------------------------------------------------- | -------------- | ------------------- |
| **Nightly**        | `https://packages-staging.xdrsiem.wazuh.info/nightly/<VERSION>/`          | Public (HTTPS) | `<version>-latest`  |
| **Nightly Backup** | `https://packages-staging.xdrsiem.wazuh.info/nightly-backup/<TIMESTAMP>/` | Public (HTTPS) | `<version>-latest`  |
| **Pre-release**    | `https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/`            | Public (HTTPS) | `<version>-<stage>` |
| **Production**     | `https://packages.wazuh.com/production/5.x/`                              | Public (HTTPS) | `<version>`         |

### Package paths by format

**DEB packages:**
```
apt/pool/main/w/<component>/<component>_<version>[-<revision>]_<arch>.deb
```

**RPM packages:**
```
yum/<component>-<version>[-<revision>].<arch>.rpm
```

**macOS packages:**
```
macos/wazuh-agent-<version>[-<revision>].<arch>.pkg
```

**Windows packages:**
```
windows/wazuh-agent-<version>[-<revision>].msi
```

### Download examples

**Nightly:**
```bash
curl -O https://packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0-latest_amd64.deb
curl -O https://packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/yum/wazuh-agent-5.0.0-latest.x86_64.rpm
curl -O https://packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/macos/wazuh-agent-5.0.0-latest.arm64.pkg
curl -O https://packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/windows/wazuh-agent-5.0.0-latest.msi
```

**Pre-release:**
```bash
curl -O https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0-beta1_amd64.deb
curl -O https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-agent-5.0.0-beta1.x86_64.rpm
```

**Production:**
```bash
curl -O https://packages.wazuh.com/production/5.x/apt/pool/main/w/wazuh-manager/wazuh-manager_5.0.0_amd64.deb
curl -O https://packages.wazuh.com/production/5.x/yum/wazuh-agent-5.0.0.x86_64.rpm
```

---

**General Notes**:
- Replace `<version>` with the target version (e.g., `5.0.0`).
- Replace `<revision>` with the package revision (e.g., `1`, `test`).
- Replace `<stage>` with the pre-release stage (e.g., `beta1`, `rc1`).
- Replace `<arch>` with your architecture:
  - **DEB packages**: `amd64`, `arm64`
  - **RPM packages**: `x86_64`, `aarch64`
  - **macOS packages**: `intel64`, `arm64`
- Adjust the package name for your component:
  - **Manager**: `wazuh-manager`
  - **Agent**: `wazuh-agent`
- These repositories are not accessible via web browser, even though some are public via HTTPS.
