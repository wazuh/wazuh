# Change Log
All notable changes to this project will be documented in this file.


## [v1.0] - 2015-11-23
- Initial Wazuh version v1.0

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
