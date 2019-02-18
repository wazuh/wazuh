---
name: 'Test: Configuration Assessment'
about: Test suite for Configuration Assessment.
title: ''
labels: ''
assignees: ''

---

# Configuration Assessment test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

Checks for every OS
---------------------

- [ ] Debian based distributions

- [ ] RHEL/CentOS 7

- [ ] RHEL/CentOS 6

- [ ] RHEL/CentOS 5

- [ ] Suse 11/12

- [ ] Windows XP/Server 2003

- [ ] Windows Server 2012

- [ ] Windows > Vista

- [ ] macOS

### Agents

- [ ] Fresh installation. Check the correct policies for each OS are installed at `ruleset/configuration-assessment`.
- [ ] Check the configuration template contains the module block with the correct policies.
- [ ] Check the rootcheck configuration doesn't contain any setting for policy monitoring.
- [ ] Try to run a policy whose requirements fail.
- [ ] Set an absolute path for a policy out of the default directory.
- [ ] Run scans for every available policy.
- [ ] The second scan just sends differences and summaries.
- [ ] Restart the agent. The whole scan should be sent to the manager but no repeated alerts must appear.
- [ ] Disable a policy (use the attribute `enabled`) and rerun the scan.

### Manager

- [ ] Check results of the first scan:
  - [ ] The DB has been filled with all the information.
  - [ ] Alerts about new checks and summaries appear in the `alerts.log` and `alerts.json`.
  - [ ] The API returns information about policies and checks.
  - [ ] See alerts on the Kibana Discover and information about the whole scan in the Conf. Assessment tab for the agent.

- [ ] Check results of subsequent scans:
  - [ ] The DB is updated.
  - [ ] Alert about the different state of a check and summary alert (when any difference)
  - [ ] When no differences between scans: Check that no alerts are triggered.
  - [ ] The Configuration Assessment tab is updated.

- [ ] Check results when a policy is disabled:
  - [ ] The DB must purge the policy information and its checks.
  - [ ] No alerts about the disabled policy.
  - [ ] The Configuration Assessment tab is updated.

- [ ] Check the configuration on demand:
  - [ ] API call.
  - [ ] Wazuh App.

Integrity
---------

- [ ] Check the scan results are resend in a random interval between 5 seconds and `configuration_assessment.request_db_interval` when the integrity check fails.
- [ ] No alerts about a resend are shown.
- [ ] Check the database is updated correctly after a recovery.

Upgrade
---------

- [ ] A warning message appears when Rootcheck is configured for policy monitoring.
- [ ] Wazuh DB must upgrade agent databases including the new tables for Configuration Assessment.
- [ ] Check the correct policies for each OS are installed at `ruleset/configuration-assessment`.
- [ ] The ruleset upgrade script updates the Configuration Assessment policies.

Memory checks
----------------

- [ ] Windows agent. Monitor memory usage and run Dr. Memory.
- [ ] Linux agent. Valgrind in `wazuh-modulesd` and `agentd`
- [ ] Manager. Valgrind in `remoted`, `analysisd` and `wazuh-modulesd`.