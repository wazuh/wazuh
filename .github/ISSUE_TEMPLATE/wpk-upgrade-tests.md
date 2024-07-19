---
name: Release Candidate - WPK upgrade tests
about: Report the results after upgrade agent via WPK.
title: Release [WAZUH VERSION] - Release Candidate [RC VERSION] - WPK upgrade tests
labels: ''
assignees: ''

---

The following issue aims to run `upgrade WPK tests` for the current release candidate, report the results, and open new issues for any encountered errors.

## WPK upgrade tests information

|Main RC issue|Version|Release candidate|Tag|Previous issue|
|---|---|---|---|---|
||||||

## Test report procedure
All individual test checks must be marked as:
|                                  |                                            |
|---------------------------------|--------------------------------------------|
| Pass | The test ran successfully. |
| Xfail | The test was expected to fail and it failed. It must be properly justified and reported in an issue.  |
| Skip | The test was not run. It must be properly justified and reported in an issue.  |
| Fail | The test failed. A new issue must be opened to evaluate and address the problem. |

All test results must have one the following statuses: 
|                                  |                                            |
|---------------------------------|--------------------------------------------|
| :green_circle:  | All checks passed. |
| :red_circle:  | There is at least one failed check. |
| :yellow_circle:  | There is at least one expected fail or skipped test and no failures. |

Any failing test must be properly addressed with a new issue, detailing the error and the possible cause. It must be included in the `Fixes` section of the current release candidate main issue.

Any expected fail or skipped test must have an issue justifying the reason. All auditors must validate the justification for an expected fail or skipped test.

An extended report of the test results must be attached as a zip or txt. This report can be used by the auditors to dig deeper into any possible failures and details.

## Tests

To evaluate this feature, it is necessary to test upgrading the agent and also the case when the upgrade fails (rollback). The `tree` command will be used to compare, before and after the upgrade/rollback process, and check that the presence, ownership and permissions of the files and directories are expected.

Wazuh versions to test (Upgrade to the current agent version):
### Linux

|OS|Version|Status|Upgrade fail|Upgrade OK|
|----|-----|------|---------------|------------------|
|CentOS 6|3.6| | | | | 
|CentOS 6|3.7| | | | |
|CentOS 6|3.13.3| | | | |
|CentOS 6|4.0.4| | | | |
|CentOS 6|4.1.5| | | | |
|CentOS 6|4.2.7| | | | |
|CentOS 6|4.3.4| | | | |
|CentOS 8|3.6| | | | |
|CentOS 8|3.7| | | | |
|CentOS 8|3.13.3| | | | |
|CentOS 8|4.0.4| | | | |
|CentOS 8|4.1.5| | | | |
|CentOS 8|4.2.7| | | | |
|CentOS 8|4.3.4| | | | |
|Ubuntu 20|3.6| | | | |
|Ubuntu 20|3.7| | | | |
|Ubuntu 20|3.13.3||  | | |
|Ubuntu 20|4.0.4||  | | |
|Ubuntu 20|4.1.5|  |||  |
|Ubuntu 20|4.2.7|  |||  |
|Ubuntu 20|4.3 ||  |  |
|openSUSE Tumbleweed|3.6| | | | |
|openSUSE Tumbleweed|3.7| | | | |
|openSUSE Tumbleweed|3.13.3|| || |
|openSUSE Tumbleweed|4.0.4|| | ||
|openSUSE Tumbleweed|4.1.5|| | ||
|openSUSE Tumbleweed|4.2.7|| || |
|openSUSE Tumbleweed|4.3| | |
|Amazon Linux 2|3.6| | | | |
|Amazon Linux 2|3.7| | | | |
|Amazon Linux 2|3.13.3|| || |
|Amazon Linux 2|4.0.4|| | ||
|Amazon Linux 2|4.1.5|| | ||
|Amazon Linux 2|4.2.7|| || |
|Amazon Linux 2|4.3| | |

### Windows

|OS|Version|Status|Upgrade fail|Upgrade OK|
|----|-----|------|---------------|------------------|
|Server 2008|3.6| | | | |
|Server 2008|3.7| | | | |
|Server 2008|3.13.3|| || |
|Server 2008|4.0.4|| | ||
|Server 2008|4.1.5|| | ||
|Server 2008|4.2.7|| || |
|Server 2008|4.3| | |
|Server 2012 R2|3.6| | | | |
|Server 2012 R2|3.7| | | | |
|Server 2012 R2|3.13.3|| || |
|Server 2012 R2|4.0.4|| | ||
|Server 2012 R2|4.1.5|| | ||
|Server 2012 R2|4.2.7|| || |
|Server 2012 R2|4.3| | |
|Server 2016|3.6| | | | |
|Server 2016|3.7| | | | |
|Server 2016|3.13.3|| || |
|Server 2016|4.0.4|| | ||
|Server 2016|4.1.5|| | ||
|Server 2016|4.2.7|| || |
|Server 2016|4.3| | |
|Server 2019|3.6| | | | |
|Server 2019|3.7| | | | |
|Server 2019|3.13.3|| || |
|Server 2019|4.0.4|| | ||
|Server 2019|4.1.5|| | ||
|Server 2019|4.2.7|| || |
|Server 2019|4.3| | |
|Windows 10|3.6| | | | |
|Windows 10|3.7| | | | |
|Windows 10|3.13.3|| || |
|Windows 10|4.0.4|| | ||
|Windows 10|4.1.5|| | ||
|Windows 10|4.2.7|| || |
|Windows 10|4.3| | |
|Server 2022|3.6| | | | |
|Server 2022|3.7| | | | |
|Server 2022|3.13.3|| || |
|Server 2022|4.0.4|| | ||
|Server 2022|4.1.5|| | ||
|Server 2022|4.2.7|| || |
|Server 2022|4.3| | |

### macOS

|OS|Version|Status|Upgrade fail|Upgrade OK|
|----|-----------|--------|-------|------------------|
| Sierra |4.3.0| || | | |
| Sierra |4.3.4| || | | |
| Catalina |4.3.0| || | | |
| Catalina |4.3.4| || | | |
| Big Sur |4.3.0| || | | |
| Big Sur |4.3.4| || | | |
| Monterey |4.3.0| || | | |
| Monterey |4.3.4| || | | |

<!--
For each operating system and version, check the following points and add a comment for each OS tested.
## Linux:
###  UPGRADE FAIL

- [ ] The wazuh home backup is restored correctly (no traces of the installation, but only the `.tar.gz` backup and the logs).
- [ ] The permissions and owners of the following directories did NOT change:
      - `/`
      - `/var`
      - `/usr`, `/usr/lib/`, `/usr/lib/systemd/`, `/usr/lib/systemd/system/`
      - `/etc`, `/etc/systemd/`, `/etc/systemd/system/`, `/etc/rc.d`, `/etc/initd.d/`, `/etc/initd.d/rc.d/`
- [ ] Wazuh service runs wazuh-control (`systemctl cat wazuh-agent.service`)
- [ ] Wazuh service runs ossec-control (`systemctl cat wazuh-agent.service`)
- [ ] The service was enabled (`systemctl is-enabled wazuh-agent.service`)
- [ ] Init file runs wazuh-control (`cat /etc/rc.d/init.d/wazuh-agent`)
- [ ] Init file runs ossec-control (`cat /etc/rc.d/init.d/wazuh-agent`)
- [ ] Wazuh as service is enabled `chkconfig --list` 
- [ ] Wazuh starts and connects when the backup is restored (`cat /var/ossec/var/run/ossec-agentd.state`)
- [ ] Wazuh starts and connects automatically when the system is rebooted.
- [ ] Restore SELinux policies (`semodule -l | grep -i wazuh`) (DISABLED)

###  UPGRADE OK

- [ ] Upgrade is performed successfully (agent connects to the manager after upgrading)
- [ ] Service starts automatically after rebooting
- [ ] Agent connects to the manager after rebooting

## Windows:
### UPGRADE FAIL
- [ ] Wazuh-Agent folder tree:  No files are lost after the rollback. The logs of the failed upgrade (`ossec.log`) are kept.
- [ ] After the rollback the agent connects to the manager
- [ ] After reboot, the Wazuh-Agent starts and connects to the manager.
- [ ] The correct Wazuh-Agent version is shown in the list of Windows' `programs and features`.
- [ ] A new version of Wazuh-Agent can be manually installed via MSI after the rollback process.

### UPGRADE OK

- [ ] Message `Upgrade finished successfully.` is shown in `upgrade.log` file.
- [ ] Wazuh service is started and the agent is connected to the manager.
- [ ] The version shown in the control panel is 4.3

## MacOS:
### UPGRADE FAIL

- [ ] Wazuh-Agent folder tree:  No files are lost after the rollback. The logs of the failed upgrade (`ossec.log`) are kept.
- [ ] After the rollback the agent connects to the manager
- [ ] After reboot, the Wazuh-Agent starts and connects to the manager.

### UPGRADE OK

- [ ] Message `Upgrade finished successfully.` is shown in `upgrade.log` file.
- [ ] Wazuh service is started and the agent is connected to the manager.
-->


## Auditors validation
The definition of done for this one is the validation of the conclusions and the test results from all auditors.

All checks from below must be accepted in order to close this issue.

- [ ]
