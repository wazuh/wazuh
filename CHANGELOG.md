# Change Log
All notable changes to this project will be documented in this file.

## [v1.1.1] - 2016-05-12

### Added

- agent_control: maximum number of agents can now be extracted using option "-m".
- maild: timeout limitation, preventing it from hang in some cases.
- Updated decoders, ruleset and rootchecks from Wazuh Ruleset v1.0.8.
- Updated changes from ossec-hids repository.

### Changed

- Avoid authd to rename agent if overplaced.
- Changed some log messages.
- Reordered directories for agent backups.
- Don't exit when client.keys is empty by default.
- Improved client.keys reloading capabilities.

### Fixed

- Fixed JSON output at rootcheck_control.
- Fixed agent compilation on OS X.
- Fixed memory issue on removing timestamps.
- Fixed segmentation fault at reported.
- Fixed segmentation fault at logcollector.

### Removed

- Removed old rootcheck options.

## [v1.1] - 2016-04-06

### Added

- Re-usage of agent ID in manage_agents and authd, with time limit.
- Added option to avoid manager from exiting when there are no keys.
- Backup of the information about an agent that's going to be deleted.
- Alerting if Authd can't add an agent because of a duplicated IP.
- Integrator with Slack and PagerDuty.
- Simplified keywords for the option "frequency".
- Added custom Reply-to e-mail header.
- Added option to syscheck to avoid showing diffs on some files.
- Created agents-timestamp file to save the agents' date of adding.

### Changed

- client.keys: No longer overwrite the name of an agent with "#-#-#-" to mark it as deleted. Instead, the name will appear with a starting "!".
- API: Distinction between duplicated and invalid name for agent.
- Stop the "ERROR: No such file or directory" for Apache.
- Changed defaults to analysisd event counter.
- Authd won't use password by default.
- Changed name of fields at JSON output from binaries.
- Upgraded rules to Wazuh Ruleset v1.07

### Fixed

- Fixed merged.mg push on Windows Agent
- Fixed Windows agent compilation issue
- Fixed glob broken implementation.
- Fixed memory corruption on the OSSEC alert decoder.
- Fixed command "useradd" on OpenBSD.
- Fixed some PostgreSQL issues.
- Allow to disable syscheck:check_perm after enable check_all.

## [v1.0.4] - 2016-02-24
​
### Added

- JSON output for manage_agents.
- Increased analysis daemon's memory size.
- Authd: Added password authorization.
- Authd: Boost speed performance at assignation of ID for agents
- Authd: New option -f *sec*. Force addding new agent (even with duplicated IP) if it was not active for the last *sec* seconds.
- manage_agents: new option -d. Force adding new agent (even with duplicated IP)
- manage_agents: Printing new agent ID on adding.

### Changed

- Authd and manage_agents won't add agents with duplicated IP.

### Fixed

- Solved duplicate IP conflicts on client.keys which prevented the new agent to connect.
- Hashing files in binary mode. Solved some problems related to integrity checksums on Windows.
- Fixed issue that made console programs not to work on Windows.

### Removed

- RESTful API no longer included in extensions/api folder. Available now at https://github.com/wazuh/wazuh-API


## [v1.0.3] - 2016-02-11

### Added

- JSON CLI outputs: ossec-control, rootcheck_control, syscheck_control, ossec-logtest and more.
- Preparing integration with RESTful API
- Upgrade version scripts
- Merge commits from ossec-hids
- Upgraded rules to Wazuh Ruleset v1.06

### Fixed

- Folders are no longer included on etc/shared
- Fixes typos on rootcheck files
- Kibana dashboards fixes

## [v1.0.2] - 2016-01-29

### Added

- Added Wazuh Ruleset updater
- Added extensions files to support ELK Stack latest versions (ES 2.x, LS 2.1, Kibana 4.3)

### Changed

- Upgraded rules to Wazuh Ruleset v1.05
- Fixed crash in reportd
- Fixed Windows EventChannel syntaxis issue
- Fixed manage_agents bulk option bug. No more "randombytes" errors.
- Windows deployment script improved

## [v1.0.1] - 2015-12-10

### Added

- Wazuh version info file
- ossec-init.conf now includes wazuh version
- Integrated with wazuh OSSEC ruleset updater
- Several new fields at JSON output (archives and alerts)
- Wazuh decoders folder

### Changed

- Decoders are now splitted in differents files.
- jsonout_out enable by default
- JSON groups improvements
- Wazuh ruleset updated to 1.0.2
- Extensions: Improved Kibana dashboards
- Extensions: Improved Windows deployment script

## [v1.0] - 2015-11-23
- Initial Wazuh version v1.0


