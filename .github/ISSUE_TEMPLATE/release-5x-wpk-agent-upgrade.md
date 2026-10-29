---
name: Release - 5.x - WPK agent upgrade
about: Report the results after running the remote upgrade (WPK) tests for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - WPK agent upgrade'
labels: 'level/task, type/test'
assignees: ''
---

The purpose of this issue is to perform remote upgrade (WPK) tests for the current stage, report the results, and open new issues for any errors encountered.

> [!NOTE]
> These tests are performed locally.

## WPK agent upgrade information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Previous WPK agent upgrade issue** | {{PREVIOUS_ISSUE}} |

## Test description

This test involves the following steps:
1. Set up the previous released version of the agent: install it and connect it to the manager.
2. Perform a remote upgrade:
   ```shell
   /var/wazuh-manager/bin/agent_upgrade -a <ID> -f /var/wazuh-manager/var/upgrade/wazuh_agent_v{{VERSION}}_<PLATFORM>.wpk
   ```
3. Verify that the upgrade completes successfully and that the agent version is updated correctly.

Please attach evidence of the following:
- Agent endpoint operating system
- Previous agent version
- New agent version
- Upgrade process output

We aim to test each WPK package on a modern platform that supports it.

| Platform | Suggested OS          |
|----------|-----------------------|
| DEB      | Ubuntu 24.04          |
| RPM      | AlmaLinux 9           |
| MSI      | Windows 11            |
| PKG      | macOS 26 Tahoe @arm64 |

## Download the manager package

```shell
curl -fLsO https://packages-dev.wazuh.com/pre-release/apt/pool/main/w/wazuh-manager/wazuh-manager_{{VERSION}}-1_amd64.deb
curl -fLsO https://packages-dev.wazuh.com/pre-release/yum/wazuh-manager-{{VERSION}}-1.x86_64.rpm
```

## Download the WPK packages

```shell
curl -fLsO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/wpk/linux/deb/amd64/wazuh_agent_v{{VERSION}}_linux_amd64.deb.wpk
curl -fLsO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/wpk/linux/rpm/x86_64/wazuh_agent_v{{VERSION}}_linux_x86_64.rpm.wpk
curl -fLsO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/wpk/macos/pkg/intel64/wazuh_agent_v{{VERSION}}_macos_intel64.pkg.wpk
curl -fLsO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/wpk/macos/pkg/arm64/wazuh_agent_v{{VERSION}}_macos_arm64.pkg.wpk
curl -fLsO https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/wpk/windows/wazuh_agent_v{{VERSION}}_windows.wpk
```

## Report procedure

All test results must include one of the following statuses:

|    | Description                                                           |
|:--:|-----------------------------------------------------------------------|
| 🟢 | All checks passed                                                     |
| 🔴 | At least one check failed                                             |
| 🟡 | At least one expected failure or skipped test, and no actual failures |

Any failed test must be documented in a new issue describing the error and possible root cause.

Any expected failure or skipped test must be justified in a corresponding issue. All auditors must review and validate these justifications.

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

| Status | Test | Failure type | New or known issues (with link) | Notes |
|---|---|---|---|---|
|  | DEB - Ubuntu 24.04 |  |  |  |
|  | RPM - AlmaLinux 9 |  |  |  |
|  | MSI - Windows 11 |  |  |  |
|  | PKG - macOS 26 Tahoe @arm64 |  |  |  |

## Auditors' validation

The definition of done for this issue includes validation of the conclusions and test results by all assigned auditors.

All of the following must be approved in order to close this issue:

- [ ] @wazuh/devel-xdrsiem-agent
- [ ] @wazuh/devel-xdrsiem-qa-release
