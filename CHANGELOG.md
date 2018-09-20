# Change Log
All notable changes to this project will be documented in this file.

## [v3.6.2]

### Changed

- Make Syscheck case insensitive. ([#1349](https://github.com/wazuh/wazuh/pull/1349))

### Fixed

- Fix 0 value at check options from Syscheck. ([1209](https://github.com/wazuh/wazuh/pull/1209))
- Prevent offline agents from generating vulnerability-detector alerts. ([#1292](https://github.com/wazuh/wazuh/pull/1292))
- Fix empty SHA256 of rotated alerts and log files. ([#1308](https://github.com/wazuh/wazuh/pull/1308))
- Fix typo in whodata alerts. ([#1242](https://github.com/wazuh/wazuh/issues/1242))
- Fix bug in whodata field extraction for Windows. ([#1233](https://github.com/wazuh/wazuh/issues/1233))
- Fixed service startup on error. ([#1324](https://github.com/wazuh/wazuh/pull/1324))
- Fix stack overflow when monitoring deep files. ([#1239](https://github.com/wazuh/wazuh/pull/1239))
- Fix bug when running quick commands with timeout of 1 second. ([#1259](https://github.com/wazuh/wazuh/pull/1259))
- Fixed getting RAM memory information from mac OS X and FreeBSD agents. ([#1203](https://github.com/wazuh/wazuh/pull/1203))
- Set connection timeout for Auth server ([#1336](https://github.com/wazuh/wazuh/pull/1336))

## [v3.6.1] 2018-09-07

### Fixed

- Fixed ID field length limit in JSON alerts, by @gandalfn. ([#1052](https://github.com/wazuh/wazuh/pull/1052))
- Fix segmentation fault when the agent version is empty in Vulnerability Detector. ([#1191](https://github.com/wazuh/wazuh/pull/1191))
- Fix bug that removes file extensions in rootcheck. ([#1197](https://github.com/wazuh/wazuh/pull/1197))
- Fixed incoherence in Client Syslog between plain-text and JSON alert input in `<location>` filter option. ([#1204](https://github.com/wazuh/wazuh/pull/1204))
- Fixed missing agent name and invalid predecoded hostname in JSON alerts. ([#1213](https://github.com/wazuh/wazuh/pull/1213))
- Fixed invalid location string in plain-text alerts. ([#1213](https://github.com/wazuh/wazuh/pull/1213))
- Fixed default stack size in threads on AIX and HP-UX. ([#1215](https://github.com/wazuh/wazuh/pull/1215))
- Fix socket error during agent restart due to daemon start/stop order. ([#1221](https://github.com/wazuh/wazuh/issues/1221))
- Fix bug when checking agent configuration in logcollector. ([#1225](https://github.com/wazuh/wazuh/issues/1225))
- Fix bug in folder recursion limit count in FIM real-time mode. ([#1226](https://github.com/wazuh/wazuh/issues/1226))
- Fixed errors when parsing AWS events in Elasticsearch. ([#1229](https://github.com/wazuh/wazuh/issues/1229))
- Fix bug when launching osquery from Wazuh. ([#1230](https://github.com/wazuh/wazuh/issues/1230))


## [v3.6.0] 2018-08-29

### Added

- Add rescanning of expanded files with wildcards in logcollector ([#332](https://github.com/wazuh/wazuh/pull/332))
- Parallelization of logcollector ([#627](https://github.com/wazuh/wazuh/pull/672))
  - Now the input of logcollector is multithreaded, reading logs in parallel.
  - A thread is created for each type of output socket.
  - Periodically rescan of new files.
  - New options have been added to internal_options.conf file.
- Added statistical functions to remoted. ([#682](https://github.com/wazuh/wazuh/pull/682))
- Rootcheck and Syscheck (FIM) will run independently. ([#991](https://github.com/wazuh/wazuh/pull/991))
- Add hash validation for binaries executed by the wodle `command`. ([#1027](https://github.com/wazuh/wazuh/pull/1027))
- Added a recursion level option to Syscheck to set the directory scanning depth. ([#1081](https://github.com/wazuh/wazuh/pull/1081))
- Added inactive agent filtering option to agent_control, syscheck_control and rootcheck control_tools. ([#1088](https://github.com/wazuh/wazuh/pull/1088))
- Added custom tags to FIM directories and registries. ([#1096](https://github.com/wazuh/wazuh/pull/1096))
- Improved AWS CloudTrail wodle by @UranusBytes ([#913](https://github.com/wazuh/wazuh/pull/913) & [#1105](https://github.com/wazuh/wazuh/pull/1105)).
- Added support to process logs from more AWS services: Guard Duty, IAM, Inspector, Macie and VPC. ([#1131](https://github.com/wazuh/wazuh/pull/1131)).
- Create script for blocking IP's using netsh-advfirewall. ([#1172](https://github.com/wazuh/wazuh/pull/1172)).

### Changed

- The maximum log length has been extended up to 64 KiB. ([#411](https://github.com/wazuh/wazuh/pull/411))
- Changed logcollector analysis message order. ([#675](https://github.com/wazuh/wazuh/pull/675))
- Let hostname field be the name of the agent, without the location part. ([#1080](https://github.com/wazuh/wazuh/pull/1080))
- The internal option `syscheck.max_depth` has been renamed to `syscheck.default_max_depth`. ([#1081](https://github.com/wazuh/wazuh/pull/1081))
- Show warning message when configuring vulnerability-detector for an agent. ([#1130](https://github.com/wazuh/wazuh/pull/1130))
- Increase the minimum waiting time from 0 to 1 seconds in Vulnerability-Detector. ([#1132](https://github.com/wazuh/wazuh/pull/1132))
- Prevent Windows agent from not loading the configuration if an AWS module block is found. ([#1143](https://github.com/wazuh/wazuh/pull/1143))
- Set the timeout to consider an agent disconnected to 1800 seconds in the framework. ([#1155](https://github.com/wazuh/wazuh/pull/1155))

### Fixed

- Fix agent ID zero-padding in alerts coming from Vulnerability Detector. ([#1083](https://github.com/wazuh/wazuh/pull/1083))
- Fix multiple warnings when agent is offline. ([#1086](https://github.com/wazuh/wazuh/pull/1086))
- Fixed minor issues in the Makefile and the sources installer on HP-UX, Solaris on SPARC and AIX systems. ([#1089](https://github.com/wazuh/wazuh/pull/1089))
- Fixed SHA256 changes messages in alerts when it is disabled. ([#1100](https://github.com/wazuh/wazuh/pull/1100))
- Fixed empty configuration blocks for Wazuh modules. ([#1101](https://github.com/wazuh/wazuh/pull/1101))
- Fix broken pipe error in Wazuh DB by Vulnerability Detector. ([#1111](https://github.com/wazuh/wazuh/pull/1111))
- Restored firewall-drop AR script for Linux. ([#1114](https://github.com/wazuh/wazuh/pull/1114))
- Fix unknown severity in Red Hat systems. ([#1118](https://github.com/wazuh/wazuh/pull/1118))
- Added a building flag to compile the SQLite library externally for the API. ([#1119](https://github.com/wazuh/wazuh/issues/1119))
- Fixed variables length when storing RAM information by Syscollector. ([#1124](https://github.com/wazuh/wazuh/pull/1124))
- Fix Red Hat vulnerability database update. ([#1127](https://github.com/wazuh/wazuh/pull/1127))
- Fix allowing more than one wodle command. ([#1128](https://github.com/wazuh/wazuh/pull/1128))
- Fixed `after_regex` offset for the decoding algorithm. ([#1129](https://github.com/wazuh/wazuh/pull/1129))
- Prevents some vulnerabilities from not being checked for Debian. ([#1166](https://github.com/wazuh/wazuh/pull/1166))
- Fixed legacy configuration for `vulnerability-detector`. ([#1174](https://github.com/wazuh/wazuh/pull/1174))
- Fix active-response scripts installation for Windows. ([#1182](https://github.com/wazuh/wazuh/pull/1182)).


### Removed

- The 'T' multiplier has been removed from option `max_output_size`. ([#1089](https://github.com/wazuh/wazuh/pull/1089))


## [v3.5.0] 2018-08-10

### Added

- Improved configuration of OVAL updates. ([#416](https://github.com/wazuh/wazuh/pull/416))
- Added selective agent software request in vulnerability-detector. ([#404](https://github.com/wazuh/wazuh/pull/404))
- Get Linux packages inventory natively. ([#441](https://github.com/wazuh/wazuh/pull/441))
- Get Windows packages inventory natively. ([#471](https://github.com/wazuh/wazuh/pull/471))
- Supporting AES encryption for manager and agent. ([#448](https://github.com/wazuh/wazuh/pull/448))
- Added Debian and Ubuntu 18 support in vulnerability-detector. ([#470](https://github.com/wazuh/wazuh/pull/470))
- Added Rids Synchronization. ([#459](https://github.com/wazuh/wazuh/pull/459))
- Added option for setting the group that the agent belongs to when registering it with authd ([#460](https://github.com/wazuh/wazuh/pull/460))
- Added option for setting the source IP when the agent registers with authd ([#460](https://github.com/wazuh/wazuh/pull/460))
- Added option to force the vulnerability detection in unsupported OS. ([#462](https://github.com/wazuh/wazuh/pull/462))
- Get network inventory natively. ([#546](https://github.com/wazuh/wazuh/pull/546))
- Add arch check for Red Hat's OVAL in vulnerability-detector. ([#625](https://github.com/wazuh/wazuh/pull/625))
- Integration with Osquery. ([#627](https://github.com/wazuh/wazuh/pull/627))
    - Enrich osquery configuration with pack files aggregation and agent labels as decorators.
    - Launch osquery daemon in background.
    - Monitor results file and send them to the manager.
    - New option in rules `<location>` to filter events by osquery.
    - Support folders in shared configuration. This makes easy to send pack folders to agents.
    - Basic ruleset for osquery events and daemon logs.
- Boost Remoted performance with multithreading. ([#649](https://github.com/wazuh/wazuh/pull/649))
    - Up to 16 parallel threads to decrypt messages from agents.
    - Limit the frequency of agent keys reloading.
    - Message input buffer in Analysisd to prevent control messages starvation in Remoted.
- Module to download shared files for agent groups dinamically. ([#519](https://github.com/wazuh/wazuh/pull/519))
    - Added group creation for files.yml if the group does not exist. ([#1010](https://github.com/wazuh/wazuh/pull/1010))
- Added scheduling options to CIS-CAT integration. ([#586](https://github.com/wazuh/wazuh/pull/586))
- Option to download the wpk using http in `agent_upgrade`. ([#798](https://github.com/wazuh/wazuh/pull/798))
- Add `172.0.0.1` as manager IP when creating `global.db`. ([#970](https://github.com/wazuh/wazuh/pull/970))
- New requests for Syscollector. ([#728](https://github.com/wazuh/wazuh/pull/728))
- `cluster_control` shows an error if the status does not exist. ([#1002](https://github.com/wazuh/wazuh/pull/1002))
- Get Windows hardware inventory natively. ([#831](https://github.com/wazuh/wazuh/pull/831))
- Get processes and ports inventory by the Syscollector module.
- Added an integration with Kaspersky Endpoint Security for Linux via Active Response. ([#1056](https://github.com/wazuh/wazuh/pull/1056))

### Changed

- Add default value for option -x in agent_control tool.
- External libraries moved to an external repository.
- Ignore OverlayFS directories on Rootcheck system scan.
- Extracts agent's OS from the database instead of the agent-info.
- Increases the maximum size of XML parser to 20KB.
- Extract CVE instead of RHSA codes into vulnerability-detector. ([#549](https://github.com/wazuh/wazuh/pull/549))
- Store CIS-CAT results into Wazuh DB. ([#568](https://github.com/wazuh/wazuh/pull/568))
- Add profile information to CIS-CAT reports. ([#658](https://github.com/wazuh/wazuh/pull/658))
- Merge external libraries into a unique shared library. ([#620](https://github.com/wazuh/wazuh/pull/620))
- Cluster log rotation: set correct permissions and store rotations in /logs/ossec. ([#667](https://github.com/wazuh/wazuh/pull/667))
- `Distinct` requests don't allow `limit=0` or `limit>maximun_limit`. ([#1007](https://github.com/wazuh/wazuh/pull/1007))
- Deprecated arguments -i, -F and -r for Authd. ([#1013](https://github.com/wazuh/wazuh/pull/1013))
- Increase the internal memory for real-time from 12 KiB to 64 KiB. ([#1062](https://github.com/wazuh/wazuh/pull/1062))

### Fixed

- Fixed invalid alerts reported by Syscollector when the event contains the word "error". ([#461](https://github.com/wazuh/wazuh/pull/461))
- Silenced Vuls integration starting and ending alerts. ([#541](https://github.com/wazuh/wazuh/pull/541))
- Fix problem comparing releases of ubuntu packages. ([#556](https://github.com/wazuh/wazuh/pull/556))
- Windows delete pending active-responses before reset agent. ([#563](https://github.com/wazuh/wazuh/pull/563))
- Fix bug in Rootcheck for Windows that searches for keys in 32-bit mode only. ([#566](https://github.com/wazuh/wazuh/pull/566))
- Alert when unmerge files fails on agent. ([#731](https://github.com/wazuh/wazuh/pull/731))
- Fixed bugs reading logs in framework. ([#856](https://github.com/wazuh/wazuh/pull/856))
- Ignore uppercase and lowercase sorting an array in framework. ([#814](https://github.com/wazuh/wazuh/pull/814))
- Cluster: reject connection if the client node has a different cluster name. ([#892](https://github.com/wazuh/wazuh/pull/892))
- Prevent `the JSON object must be str, not 'bytes'` error. ([#997](https://github.com/wazuh/wazuh/pull/997))
- Fix long sleep times in vulnerability detector.
- Fix inconsistency in the alerts format for the manager in vulnerability-detector.
- Fix bug when processing the packages in vulnerability-detector.
- Prevent to process Syscollector events by the JSON decoder. ([#674](https://github.com/wazuh/wazuh/pull/674))
- Stop Syscollector data storage into Wazuh DB when an error appears. ([#674](https://github.com/wazuh/wazuh/pull/674))
- Fix bug in Syscheck that reported false positive about removed files. ([#1044](https://github.com/wazuh/wazuh/pull/1044))
- Fix bug in Syscheck that misinterpreted no_diff option. ([#1046](https://github.com/wazuh/wazuh/pull/1046))
- Fixes in file integrity monitoring for Windows. ([#1062](https://github.com/wazuh/wazuh/pull/1062))
  - Fix Windows agent crash if FIM fails to extract the file owner.
  - Prevent FIM real-time mode on Windows from stopping if the internal buffer gets overflowed.
- Prevent large logs from flooding the log file by Logcollector. ([#1067](https://github.com/wazuh/wazuh/pull/1067))
- Fix allowing more than one wodle command and compute command timeout when ignore_output is enabled. ([#1102](https://github.com/wazuh/wazuh/pull/1102))

### Removed

- Deleted Lua language support.
- Deleted integration with Vuls. ([#879](https://github.com/wazuh/wazuh/issues/879))
- Deleted agent_list tool, replaced by agent_control. ([#ba0265b](https://github.com/wazuh/wazuh/commit/ba0265b6e9e3fed133d60ef2df3450fdf26f7da4#diff-f57f2991a6aa25fe45d8036c51bf8b4d))

## [v3.4.0] 2018-07-24

### Added

- Support for SHA256 checksum in Syscheck (by @arshad01). ([#410](https://github.com/wazuh/wazuh/pull/410))
- Added an internal option for Syscheck to tune the RT alerting delay. ([#434](https://github.com/wazuh/wazuh/pull/434))
- Added two options in the tag <auto_ignore> `frequency` and `timeframe` to hide alerts when they are played several times in a given period of time. ([#857](https://github.com/wazuh/wazuh/pull/857))
- Include who-data in Syscheck for file integrity monitoring. ([#756](https://github.com/wazuh/wazuh/pull/756))
  - Linux Audit setup and monitoring to watch directories configured with who-data.
  - Direct communication with Auditd on Linux to catch who-data related events.
  - Setup of SACL for monitored directories on Windows.
  - Windows Audit events monitoring through Windows Event Channel.
  - Auto setup of audit configuration and reset when the agent quits.
- Syscheck in frequency time show alerts from deleted files. ([#857](https://github.com/wazuh/wazuh/pull/857))
- Added an option `target` to customize output format per-target in Logcollector. ([#863](https://github.com/wazuh/wazuh/pull/863))
- New option for the JSON decoder to choose the treatment of NULL values. ([#677](https://github.com/wazuh/wazuh/pull/677))
- Remove old snapshot files for FIM. ([#872](https://github.com/wazuh/wazuh/pull/872))
- Distinct operation in agents. ([#920](https://github.com/wazuh/wazuh/pull/920))
- Added support for unified WPK. ([#865](https://github.com/wazuh/wazuh/pull/865))
- Added missing debug options for modules in the internal options file. ([#901](https://github.com/wazuh/wazuh/pull/901))
- Added recursion limits when reading directories. ([#947](https://github.com/wazuh/wazuh/pull/947))

### Changed

- Renamed cluster _client_ node type to ___worker___ ([#850](https://github.com/wazuh/wazuh/pull/850)).
- Changed a descriptive message in the alert showing what attributes changed. ([#857](https://github.com/wazuh/wazuh/pull/857))
- Change visualization of Syscheck alerts. ([#857](https://github.com/wazuh/wazuh/pull/857))
- Add all the available fields in the Syscheck messages from the Wazuh configuration files. ([#857](https://github.com/wazuh/wazuh/pull/857))
- Now the no_full_log option only affects JSON alerts. ([#881](https://github.com/wazuh/wazuh/pull/881))
- Delete temporary files when stopping Wazuh. ([#732](https://github.com/wazuh/wazuh/pull/732))
- Send OpenSCAP checks results to a FIFO queue instead of temporary files. ([#732](https://github.com/wazuh/wazuh/pull/732))
- Default behavior when starting Syscheck and Rootcheck components. ([#829](https://github.com/wazuh/wazuh/pull/829))
  - They are disabled if not appear in the configuration.
  - They can be set up as empty blocks in the configuration, applying their default values.
  - Improvements of error and information messages when they start.
- Improve output of `DELETE/agents` when no agents were removed. ([#868](https://github.com/wazuh/wazuh/pull/868))
- Include the file owner SID in Syscheck alerts.
- Change no previous checksum error message to information log. ([#897](https://github.com/wazuh/wazuh/pull/897))
- Changed default Syscheck scan speed: 100 files per second. ([#975](https://github.com/wazuh/wazuh/pull/975))
- Show network protocol used by the agent when connecting to the manager. ([#980](https://github.com/wazuh/wazuh/pull/980))

### Fixed

- Syscheck RT process granularized to make frequency option more accurate. ([#434](https://github.com/wazuh/wazuh/pull/434))
- Fixed registry_ignore problem on Syscheck for Windows when arch="both" was used. ([#525](https://github.com/wazuh/wazuh/pull/525))
- Allow more than 256 directories in real-time for Windows agent using recursive watchers. ([#540](https://github.com/wazuh/wazuh/pull/540))
- Fix weird behavior in Syscheck when a modified file returns back to its first state. ([#434](https://github.com/wazuh/wazuh/pull/434))
- Replace hash value xxx (not enabled) for n/a if the hash couldn't be calculated. ([#857](https://github.com/wazuh/wazuh/pull/857))
- Do not report uid, gid or gname on Windows (avoid user=0). ([#857](https://github.com/wazuh/wazuh/pull/857))
- Several fixes generating sha256 hash. ([#857](https://github.com/wazuh/wazuh/pull/857))
- Fixed the option report_changes configuration. ([#857](https://github.com/wazuh/wazuh/pull/857))
- Fixed the 'report_changes' configuration when 'sha1' option is not set. ([#857](https://github.com/wazuh/wazuh/pull/857))
- Fix memory leak reading logcollector config. ([#884](https://github.com/wazuh/wazuh/pull/884))
- Fixed crash in Slack integration for alerts that don't have full log. ([#880](https://github.com/wazuh/wazuh/pull/880))
- Fixed active-responses.log definition path on Windows configuration. ([#739](https://github.com/wazuh/wazuh/pull/739))
- Added warning message when updating Syscheck/Rootcheck database to restart the manager. ([#817](https://github.com/wazuh/wazuh/pull/817))
- Fix PID file creation checking. ([#822](https://github.com/wazuh/wazuh/pull/822))
  - Check that the PID file was created and written.
  - This would prevent service from running multiple processes of the same daemon.
- Fix reading of Windows platform for 64 bits systems. ([#832](https://github.com/wazuh/wazuh/pull/832))
- Fixed Syslog output parser when reading the timestamp from the alerts in JSON format. ([#843](https://github.com/wazuh/wazuh/pull/843))
- Fixed filter for `gpg-pubkey` packages in Syscollector. ([#847](https://github.com/wazuh/wazuh/pull/847))
- Fixed bug in configuration when reading the `repeated_offenders` option in Active Response. ([#873](https://github.com/wazuh/wazuh/pull/873))
- Fixed variables parser when loading rules. ([#855](https://github.com/wazuh/wazuh/pull/855))
- Fixed parser files names in the Rootcheck scan. ([#840](https://github.com/wazuh/wazuh/pull/840))
- Removed frequency offset in rules. ([#827](https://github.com/wazuh/wazuh/pull/827)).
- Fix memory leak reading logcollector config. ([#884](https://github.com/wazuh/wazuh/pull/884))
- Fixed sort agents by status in `GET/agents` API request. ([#810](https://github.com/wazuh/wazuh/pull/810))
- Added exception when no agents are selected to restart. ([#870](https://github.com/wazuh/wazuh/pull/870))
- Prevent files from remaining open in the cluster. ([#874](https://github.com/wazuh/wazuh/pull/874))
- Fix network unreachable error when cluster starts. ([#800](https://github.com/wazuh/wazuh/pull/800))
- Fix empty rules and decoders file check. ([#887](https://github.com/wazuh/wazuh/pull/887))
- Prevent to access an unexisting hash table from 'whodata' thread. ([#911](https://github.com/wazuh/wazuh/pull/911))
- Fix CA verification with more than one 'ca_store' definitions. ([#927](https://github.com/wazuh/wazuh/pull/927))
- Fix error in syscollector API calls when Wazuh is installed in a directory different than `/var/ossec`. ([#942](https://github.com/wazuh/wazuh/pull/942)).
- Fix error in CentOS 6 when `wazuh-cluster` is disabled. ([#944](https://github.com/wazuh/wazuh/pull/944)).
- Fix Remoted connection failed warning in TCP mode due to timeout. ([#958](https://github.com/wazuh/wazuh/pull/958))
- Fix option 'rule_id' in syslog client. ([#979](https://github.com/wazuh/wazuh/pull/979))
- Fixed bug in legacy agent's server options that prevented it from setting port and protocol.

## [v3.3.1] 2018-06-18

### Added

- Added `total_affected_agents` and `total_failed_ids` to the `DELETE/agents` API request. ([#795](https://github.com/wazuh/wazuh/pull/795))

### Changed

- Management of empty blocks in the configuration files. ([#781](https://github.com/wazuh/wazuh/pull/781))
- Verify WPK with Wazuh CA by default. ([#799](https://github.com/wazuh/wazuh/pull/799))

### Fixed

- Windows prevents agent from renaming file. ([#773](https://github.com/wazuh/wazuh/pull/773))
- Fix manager-agent version comparison in remote upgrades. ([#765](https://github.com/wazuh/wazuh/pull/765))
- Fix log flooding when restarting agent while the merged file is being receiving. ([#788](https://github.com/wazuh/wazuh/pull/788))
- Fix issue when overwriting rotated logs in Windows agents. ([#776](https://github.com/wazuh/wazuh/pull/776))
- Prevent OpenSCAP module from running on Windows agents (incompatible). ([#777](https://github.com/wazuh/wazuh/pull/777))
- Fix issue in file changes report for FIM on Linux when a directory contains a backslash. ([#775](https://github.com/wazuh/wazuh/pull/775))
- Fixed missing `minor` field in agent data managed by the framework. ([#771](https://github.com/wazuh/wazuh/pull/771))
- Fixed missing `build` and `key` fields in agent data managed by the framework. ([#802](https://github.com/wazuh/wazuh/pull/802))
- Fixed several bugs in upgrade agents ([#784](https://github.com/wazuh/wazuh/pull/784)):
    - Error upgrading an agent with status `Never Connected`.
    - Fixed API support.
    - Sockets were not closing properly.
- Cluster exits showing an error when an error occurs. ([#790](https://github.com/wazuh/wazuh/pull/790))
- Fixed bug when cluster control or API cannot request the list of nodes to the master. ([#762](https://github.com/wazuh/wazuh/pull/762))
- Fixed bug when the `agent.conf` contains an unrecognized module. ([#796](https://github.com/wazuh/wazuh/pull/796))
- Alert when unmerge files fails on agent. ([#731](https://github.com/wazuh/wazuh/pull/731))
- Fix invalid memory access when parsing ruleset configuration. ([#787](https://github.com/wazuh/wazuh/pull/787))
- Check version of python in cluster control. ([#760](https://github.com/wazuh/wazuh/pull/760))
- Removed duplicated log message when Rootcheck is disabled. ([#783](https://github.com/wazuh/wazuh/pull/783))
- Avoid infinite attempts to download CVE databases when it fails. ([#792](https://github.com/wazuh/wazuh/pull/792))


## [v3.3.0] 2018-06-06

### Added

- Supporting multiple socket output in Logcollector. ([#395](https://github.com/wazuh/wazuh/pull/395))
- Allow inserting static field parameters in rule comments. ([#397](https://github.com/wazuh/wazuh/pull/397))
- Added an output format option for Logcollector to build custom logs. ([#423](https://github.com/wazuh/wazuh/pull/423))
- Included millisecond timing in timestamp to JSON events. ([#467](https://github.com/wazuh/wazuh/pull/467))
- Added an option in Analysisd to set input event offset for plugin decoders. ([#512](https://github.com/wazuh/wazuh/pull/512))
- Allow decoders mix plugin and multiregex children. ([#602](https://github.com/wazuh/wazuh/pull/602))
- Added the option to filter by any field in `get_agents_overview`, `get_agent_group` and `get_agents_without_group` functions of the Python framework. ([#743](https://github.com/wazuh/wazuh/pull/743))

### Changed

- Add default value for option -x in agent_upgrade tool.
- Changed output of agents in cluster control. ([#741](https://github.com/wazuh/wazuh/pull/741))

### Fixed

- Fix bug in Logcollector when removing duplicate localfiles. ([#402](https://github.com/wazuh/wazuh/pull/402))
- Fix memory error in Logcollector when using wildcards.
- Prevent command injection in Agentless daemon. ([#600](https://github.com/wazuh/wazuh/pull/600))
- Fixed bug getting the agents in cluster control. ([#741](https://github.com/wazuh/wazuh/pull/741))
- Prevent Logcollector from reporting an error when a path with wildcards matches no files.
- Fixes the feature to group with the option multi-line. ([#754](https://github.com/wazuh/wazuh/pull/754))


## [v3.2.4] 2018-06-01

### Fixed
- Fixed segmentation fault in maild when `<queue-size>` is included in the global configuration.
- Fixed bug in Framework when retrieving mangers logs. ([#644](https://github.com/wazuh/wazuh/pull/644))
- Fixed bug in clusterd to prevent the synchronization of `.swp` files. ([#694](https://github.com/wazuh/wazuh/pull/694))
- Fixed bug in Framework parsing agent configuration. ([#681](https://github.com/wazuh/wazuh/pull/681))
- Fixed several bugs using python3 with the Python framework. ([#701](https://github.com/wazuh/wazuh/pull/701))


## [v3.2.3] 2018-05-28

### Added

- New internal option to enable merged file creation by Remoted. ([#603](https://github.com/wazuh/wazuh/pull/603))
- Created alert item for GDPR and GPG13. ([#608](https://github.com/wazuh/wazuh/pull/608))
- Add support for Amazon Linux in vulnerability-detector.
- Created an input queue for Analysisd to prevent Remoted starvation. ([#661](https://github.com/wazuh/wazuh/pull/661))

### Changed

- Set default agent limit to 14.000 and file descriptor limit to 65.536 per process. ([#624](https://github.com/wazuh/wazuh/pull/624))
- Cluster improvements.
    - New protocol for communications.
    - Inverted communication flow: clients start communications with the master.
    - Just the master address is required in the `<nodes>` list configuration.
    - Improved synchronization algorithm.
    - Reduced the number of processes to one: `wazuh-clusterd`.
- Cluster control tool improvements: outputs are the same regardless of node type.
- The default input queue for remote events has been increased to 131072 events. ([#660](https://github.com/wazuh/wazuh/pull/660))
- Disconnected agents will no longer report vulnerabilities. ([#666](https://github.com/wazuh/wazuh/pull/666))

### Fixed

- Fixed agent wait condition and improve logging messages. ([#550](https://github.com/wazuh/wazuh/pull/550))
- Fix race condition in settings load time by Windows agent. ([#551](https://github.com/wazuh/wazuh/pull/551))
- Fix bug in Authd that prevented it from deleting agent-info files when removing agents.
- Fix bug in ruleset that did not overwrite the `<info>` option. ([#584](https://github.com/wazuh/wazuh/issues/584))
- Fixed bad file descriptor error in Wazuh DB ([#588](https://github.com/wazuh/wazuh/issues/588))
- Fixed unpredictable file sorting when creating merged files. ([#599](https://github.com/wazuh/wazuh/issues/599))
- Fixed race condition in Remoted when closing connections.
- Fix epoch check in vulnerability-detector.
- Fixed hash sum in logs rotation. ([#636](https://github.com/wazuh/wazuh/issues/636))
- Fixed cluster CPU usage.
- Fixed invalid deletion of agent timestamp entries. ([#639](https://github.com/wazuh/wazuh/issues/639))
- Fixed segmentation fault in logcollector when multi-line is applied to a remote configuration. ([#641](https://github.com/wazuh/wazuh/pull/641))
- Fixed issue in Syscheck that may leave the process running if the agent is stopped quickly. ([#671](https://github.com/wazuh/wazuh/pull/671))

### Removed

- Removed cluster database and internal cluster daemon.


## [v3.2.2] 2018-05-07

### Added

- Created an input queue for Remoted to prevent agent connection starvation. ([#509](https://github.com/wazuh/wazuh/pull/509))

### Changed

- Updated Slack integration. ([#443](https://github.com/wazuh/wazuh/pull/443))
- Increased connection timeout for remote upgrades. ([#480](https://github.com/wazuh/wazuh/pull/480))
- Vulnerability-detector does not stop agents detection if it fails to find the software for one of them.
- Improve the version comparator algorithm in vulnerability-detector. ([#508](https://github.com/wazuh/wazuh/pull/508/files))

### Fixed

- Fixed bug in labels settings parser that may make Agentd or Logcollector crash.
- Fixed issue when setting multiple `<server-ip>` stanzas in versions 3.0 - 3.2.1. ([#433](https://github.com/wazuh/wazuh/pull/433))
- Fixed bug when socket database messages are not sent correctly. ([#435](https://github.com/wazuh/wazuh/pull/435))
- Fixed unexpected stop in the sources installer when overwriting a previous corrupt installation.
- Added a synchronization timeout in the cluster to prevent it from blocking ([#447](https://github.com/wazuh/wazuh/pull/447))
- Fixed issue in CSyslogd when filtering by rule group. ([#446](https://github.com/wazuh/wazuh/pull/446))
- Fixed error on DB daemon when parsing rules with options introduced in version 3.0.0.
- Fixed unrecognizable characters error in Windows version name. ([#478](https://github.com/wazuh/wazuh/pull/478))
- Fix Authd client in old versions of Windows ([#479](https://github.com/wazuh/wazuh/pull/479))
- Cluster's socket management improved to use persistent connections ([#481](https://github.com/wazuh/wazuh/pull/481))
- Fix memory corruption in Syscollector decoder and memory leaks in Vulnerability Detector. ([#482](https://github.com/wazuh/wazuh/pull/482))
- Fixed memory corruption in Wazuh DB autoclosing procedure.
- Fixed dangling db files at DB Sync module folder. ([#489](https://github.com/wazuh/wazuh/pull/489))
- Fixed agent group file deletion when using Authd.
- Fix memory leak in Maild with JSON input. ([#498](https://github.com/wazuh/wazuh/pull/498))
- Fixed remote command switch option. ([#504](https://github.com/wazuh/wazuh/pull/504))

## [v3.2.1] 2018-03-03

### Added

- Added option in Makefile to disable CIS-CAT module. ([#381](https://github.com/wazuh/wazuh/pull/381))
- Added field `totalItems` to `GET/agents/purgeable/:timeframe` API call. ([#385](https://github.com/wazuh/wazuh/pull/385))

### Changed

- Giving preference to use the selected Java over the default one in CIS-CAT wodle.
- Added delay between message delivery for every module. ([#389](https://github.com/wazuh/wazuh/pull/389))
- Verify all modules for the shared configuration. ([#408](https://github.com/wazuh/wazuh/pull/408))
- Updated OpenSSL library to 1.1.0g.
- Insert agent labels in JSON archives no matter the event matched a rule.
- Support for relative/full/network paths in the CIS-CAT configuration. ([#419](https://github.com/wazuh/wazuh/pull/419))
- Improved cluster control to give more information. ([#421](https://github.com/wazuh/wazuh/pull/421))
- Updated rules for CIS-CAT.
- Removed unnecessary compilation of vulnerability-detector in agents.
- Increased wazuh-modulesd's subprocess pool.
- Improved the agent software recollection by Syscollector.

### Fixed

- Fixed crash in Agentd when testing Syscollector configuration from agent.conf file.
- Fixed duplicate alerts in Vulnerability Detector.
- Fixed compiling issues in Solaris and HP-UX.
- Fixed bug in Framework when listing directories due to permissions issues.
- Fixed error handling in CIS-CAT module. ([#401](https://github.com/wazuh/wazuh/pull/401))
- Fixed some defects reported by Coverity. ([#406](https://github.com/wazuh/wazuh/pull/406))
- Fixed OS name detection in macOS and old Linux distros. ([#409](https://github.com/wazuh/wazuh/pull/409))
- Fixed linked in HP-UX.
- Fixed Red Hat detection in vulnerability-detector.
- Fixed segmentation fault in wazuh-cluster when files path is too long.
- Fixed a bug getting groups and searching by them in `GET/agents` API call. ([#390](https://github.com/wazuh/wazuh/pull/390))
- Several fixes and improvements in cluster.
- Fixed bug in wazuh-db when closing exceeded databases in transaction.
- Fixed bug in vulnerability-detector that discarded valid agents.
- Fixed segmentation fault in Windows agents when getting OS info.
- Fixed memory leaks in vulnerability-detector and CIS-CAT wodle.
- Fixed behavior when working directory is not found in CIS-CAT wodle.

## [v3.2.0] 2018-02-13

### Added
- Added support to synchronize custom rules and decoders in the cluster.([#344](https://github.com/wazuh/wazuh/pull/344))
- Add field `status` to `GET/agents/groups/:group_id` API call.([#338](https://github.com/wazuh/wazuh/pull/338))
- Added support for Windows to CIS-CAT integration module ([#369](https://github.com/wazuh/wazuh/pull/369))
- New Wazuh Module "aws-cloudtrail" fetching logs from S3 bucket. ([#351](https://github.com/wazuh/wazuh/pull/351))
- New Wazuh Module "vulnerability-detector" to detect vulnerabilities in agents and managers.

### Fixed
- Fixed oscap.py to support new versions of OpenSCAP scanner.([#331](https://github.com/wazuh/wazuh/pull/331))
- Fixed timeout bug when the cluster port was closed. ([#343](https://github.com/wazuh/wazuh/pull/343))
- Improve exception handling in `cluster_control`. ([#343](https://github.com/wazuh/wazuh/pull/343))
- Fixed bug in cluster when receive an error response from client. ([#346](https://github.com/wazuh/wazuh/pull/346))
- Fixed bug in framework when the manager is installed in different path than /var/ossec. ([#335](https://github.com/wazuh/wazuh/pull/335))
- Fixed predecoder hostname field in JSON event output.
- Several fixes and improvements in cluster.

## [v3.1.0] 2017-12-22

### Added

- New Wazuh Module "command" for asynchronous command execution.
- New field "predecoder.timestamp" for JSON alerts including timestamp from logs.
- Added reload action to ossec-control in local mode.
- Add duration control of a cluster database synchronization.
- New internal option for agents to switch applying shared configuration.
- Added GeoIP address finding for input logs in JSON format.
- Added alert and archive output files rotation capabilities.
- Added rule option to discard field "firedtimes".
- Added VULS integration for running vulnerability assessments.
- CIS-CAT Wazuh Module to scan CIS policies.

### Changed

- Keepping client.keys file permissions when modifying it.
- Improve Rootcheck formula to select outstanding defects.
- Stop related daemon when disabling components in ossec-control.
- Prevented cluster daemon from starting on RHEL 5 or older.
- Let Syscheck report file changes on first scan.
- Allow requests by node name in cluster_control binary.
- Improved help of cluster_control binary.
- Integrity control of files in the cluster.

### Fixed

- Fixed netstat command in localfile configuration.
- Fixed error when searching agents by ID.
- Fixed syslog format pre-decoder for logs with missing (optional) space after tag.
- Fixed alert ID when plain-text alert output disabled.
- Fixed Monitord freezing when a sendmail-like executable SMTP server is set.
- Fixed validation of Active Response used by agent_control.
- Allow non-ASCII characters in Windows version string.

## [v3.0.0] 2017-12-12

### Added

- Added group property for agents to customize shared files set.
- Send shared files to multiple agents in parallel.
- New decoder plugin for logs in JSON format with dynamic fields definition.
- Brought framework from API to Wazuh project.
- Show merged files MD5 checksum by agent_control and framework.
- New reliable request protocol for manager-agent communication.
- Remote agent upgrades with signed WPK packages.
- Added option for Remoted to prevent it from writing shared merged file.
- Added state for Agentd and Windows agent to notify connection state and metrics.
- Added new JSON log format for local file monitoring.
- Added OpenSCAP SSG datastream content for Ubuntu Trusty Tahr.
- Field "alert_id" in JSON alerts (by Dan Parriott).
- Added support of "any" IP address to OSSEC batch manager (by Jozef Reisinger).
- Added ossec-agent SElinux module (by kreon).
- Added previous output to JSON output (by João Soares).
- Added option for Authd to specify the allowed cipher list (by James Le Cuirot).
- Added option for cipher suites in Authd settings.
- Added internal option for Remoted to set the shared configuration reloading time.
- Auto restart agents when new shared configuration is pushed from the manager.
- Added native support for Systemd.
- Added option to register unlimited agents in Authd.
- New internal option to limit the number of file descriptors in Analysisd and Remoted.
- Added new state "pending" for agents.
- Added internal option to disable real-time DB synchronization.
- Allow multiple manager stanzas in Agentd settings.
- New internal option to limit the receiving time in TCP mode.
- Added manager hostname data to agent information.
- New option for rotating internal logs by size.
- Added internal option to enable or disable daily rotation of internal logs.
- Added command option for Monitord to overwrite 'day_wait' parameter.
- Adding templates and sample alert for Elasticsearch 6.0.
- Added option to enable/disable Authd on install and auto-generate certificates.
- Pack secure TCP messages into a single packet.
- Added function to install SCAP policies depending on OS version.
- Added integration with Virustotal.
- Added timeout option for TCP sockets in Remoted and Agentd.
- Added option to start the manager after installing.
- Added a cluster of managers (`wazuh-clusterd`) and a script to control it (`cluster_control`).

### Changed

- Increased shared file delivery speed when using TCP.
- Increased TCP listening socket backlog.
- Changed Windows agent UI panel to show revision number instead of installation date.
- Group every decoded field (static and dynamic fields) into a data object for JSON alerts.
- Reload shared files by Remoted every 10 minutes.
- Increased string size limit for XML reader to 4096 bytes.
- Updated Logstash configuration and Elasticsearch mappings.
- Changed template fields structure for Kibana dashboards.
- Increased dynamic field limit to 1024, and default to 256.
- Changed agent buffer 'length' parameter to 'queue_size'.
- Changed some Rootcheck error messages to verbose logs.
- Removed unnecessary message by manage_agents advising to restart Wazuh manager.
- Update PF tables Active response (by d31m0).
- Create the users and groups as system users and groups in specs (by Dan Parriott).
- Show descriptive errors when an agent loses the connection using TCP.
- Prevent agents with the same name as the manager host from getting added.
- Changed 'message' field to 'data' for successful agent removing response in Authd API.
- Changed critical error to standard error in Syslog Remoted when no access list has been configured.
- Ignore hidden files in shared folder for merged file.
- Changed agent notification time values: notify time to 1 minute and reconnect time to 5 minutes.
- Prevent data field from being inserted into JSON alerts when it's empty.
- Spelling corrections (by Josh Soref).
- Moved debug messages when updating shared files to level 2.
- Do not create users ossecm or ossecr on agents.
- Upgrade netstat command in Logcollector.
- Prevent Monitord and DB sync module from dealing with agent files on local installations.
- Speed up DB syncing by keeping databases opened and an inotify event queue.
- Merge server's IP and hostname options to one setting.
- Enabled Active Response by default in both Windows and UNIX.
- Make Monitord 'day_wait' internal option affect log rotation.
- Extend Monitord 'day_wait' internal option range.
- Prevent Windows agent from log error when the manager disconnected.
- Improve Active Response filtering options.
- Use init system (Systemd/SysVinit) to restart Wazuh when upgrading.
- Added possibility of filtering agents by manager hostname in the Framework.
- Prevent installer from overwriting agent.conf file.
- Cancel file sending operation when agent socket is closed.
- Clean up agent shared folder before unmerging shared configuration.
- Print descriptive error when request socket refuses connection due to AR disabled.
- Extend Logcollector line burst limit range.
- Fix JSON alert file reloading when the file is rotated.
- Merge IP and Hostname server configuration into "Address" field.
- Improved TCP transmission performance by packing secure messages.

### Fixed

- Fixed wrong queries to get last Syscheck and Rootcheck date.
- Prevent Logcollector keep-alives from being stored on archives.json.
- Fixed length of random message within keep-alives.
- Fixed Windows version detection for Windows 8 and newer.
- Fixed incorrect CIDR writing on client.keys by Authd.
- Fixed missing buffer flush by Analysisd when updating Rootcheck database.
- Stop Wazuh service before removing folder to reinstall.
- Fixed Remoted service for Systemd (by Phil Porada).
- Fixed Administrator account mapping in Windows agent installation (by andrewm0374@gmail.com).
- Fixed MySQL support in dbd (by andrewm0374@gmail.com).
- Fixed incorrect warning when unencrypting messages (by Dan Parriott).
- Fixed Syslog mapping for alerts via Csyslogd (by Dan Parriott).
- Fixed syntax error in the creation of users in Solaris 11.2 (by Pedro Flor).
- Fixed some warnings that appeared when compiling on Fedora 26.
- Fixed permission issue in logs folder.
- Fixed issue in Remoted that prevented it from send shared configuration when it changed.
- Fixed Windows agent compilation compability with CentOS.
- Supporting different case from password prompt in Agentless (by Jesus Fidalgo).
- Fix bad detection of inotify queue overflowed.
- Fix repetitive error when a rule's diff file is empty.
- Fixed log group permission when created by a daemon running as root.
- Prevented Agentd from logging too many errors when restarted while receiving the merged file.
- Prevented Remoted from sending data to disconnected agents in TCP mode.
- Fixed alerts storage in PostgreSQL databases.
- Fixed invalid previous output data in JSON alerts.
- Fixed memory error in modulesd for invalid configurations.
- Fixed default Auth configuration to support custom install directory.
- Fixed directory transversal vulnerability in Active response commands.
- Fixed Active response timeout accuracy.
- Fixed race conditions in concurrent transmissions over TCP.

### Removed

- Removed Picviz support (by Dan Parriott).


## [v2.1.1] - 2017-09-21

### Changed

- Improved errors messages related to TCP connection queue.
- Changed info log about unsupported FS checking in Rootcheck scan to debug messages.
- Prevent Modules daemon from giving critical error when no wodles are enabled.

### Fixed

- Fix endianess incompatibility in agents on SPARC when connecting via TCP.
- Fix bug in Authd that made it crash when removing keys.
- Fix race condition in Remoted when writing logs.
- Avoid repeated errors by Remoted when sending data to a disconnected agent.
- Prevented Monitord from rotating non-existent logs.
- Some fixes to support HP-UX.
- Prevent processes from sending events when TCP connection is lost.
- Fixed output header by Syslog client when reading JSON alerts.
- Fixed bug in Integrator settings parser when reading rules list.

## [v2.1.0] - 2017-08-14

### Added

- Rotate and compress log feature.
- Labeling data for agents to be shown in alerts.
- New 'auth' configuration template.
- Make manage_agents capable of add and remove agents via Authd.
- Implemented XML configuration for Authd.
- Option -F for Authd to force insertion if it finds duplicated name.
- Local auth client to manage agent keys.
- Added OS name and version into global.db.
- Option for logging in JSON format.
- Allow maild to send through a sendmail-like executable (by James Le Cuirot).
- Leaky bucket-like buffer for agents to prevent network flooding.
- Allow Syslog client to read JSON alerts.
- Allow Mail reporter to read JSON alerts.
- Added internal option to tune Rootcheck sleep time.
- Added route-null Active Response script for Windows 2012 (by @CrazyLlama).

### Changed

- Updated SQLite library to 3.19.2.
- Updated zlib to 1.2.11.
- Updated cJSON library to 1.4.7.
- Change some manage_agents option parameters.
- Run Auth in background by default.
- Log classification as debug, info, warning, error and critical.
- Limit number of reads per cycle by Logcollector to prevent log starvation.
- Limit OpenSCAP module's event forwarding speed.
- Increased debug level of repeated Rootcheck messages.
- Send events when OpenSCAP starts and finishes scans.
- Delete PID files when a process exits not due to a signal.
- Change error messages due to SSL handshake failure to debug messages.
- Force group addition on installation for compatibility with LDAP (thanks to Gary Feltham).

### Fixed

- Fixed compiling error on systems with no OpenSSL.
- Fixed compiling warning at manage_agents.
- Fixed ossec-control enable/disable help message.
- Fixed unique aperture of random device on Unix.
- Fixed file sum comparison bug at Syscheck realtime engine. (Thanks to Arshad Khan)
- Close analysisd if alert outputs are disabled for all formats.
- Read Windows version name for versions newer than Windows 8 / Windows Server 2012.
- Fixed error in Analysisd that wrote Syscheck and Rootcheck databases of re-added agents on deleted files.
- Fixed internal option to configure the maximum labels' cache time.
- Fixed Auth password parsing on client side.
- Fix bad agent ID assignation in Authd on i686 architecture.
- Fixed Logcollector misconfiguration in Windows agents.

### Removed

- Remove unused message queue to send alerts from Authd.


## [v2.0.1] - 2017-07-19

### Changed

- Changed random data generator for a secure OS-provided generator.
- Changed Windows installer file name (depending on version).
- Linux distro detection using standard os-release file.
- Changed some URLs to documentation.
- Disable synchronization with SQLite databases for Syscheck by default.
- Minor changes at Rootcheck formatter for JSON alerts.
- Added debugging messages to Integrator logs.
- Show agent ID when possible on logs about incorrectly formatted messages.
- Use default maximum inotify event queue size.
- Show remote IP on encoding format errors when unencrypting messages.
- Remove temporary files created by Syscheck changes reports.
- Remove temporary Syscheck files for changes reporting by Windows installer when upgrading.

### Fixed

- Fixed resource leaks at rules configuration parsing.
- Fixed memory leaks at rules parser.
- Fixed memory leaks at XML decoders parser.
- Fixed TOCTOU condition when removing directories recursively.
- Fixed insecure temporary file creation for old POSIX specifications.
- Fixed missing agentless devices identification at JSON alerts.
- Fixed FIM timestamp and file name issue at SQLite database.
- Fixed cryptographic context acquirement on Windows agents.
- Fixed debug mode for Analysisd.
- Fixed bad exclusion of BTRFS filesystem by Rootcheck.
- Fixed compile errors on macOS.
- Fixed option -V for Integrator.
- Exclude symbolic links to directories when sending FIM diffs (by Stephan Joerrens).
- Fixed daemon list for service reloading at ossec-control.
- Fixed socket waiting issue on Windows agents.
- Fixed PCI_DSS definitions grouping issue at Rootcheck controls.
- Fixed segmentation fault bug when stopping on CentOS 5.
- Fixed compatibility with AIX.
- Fixed race conditions in ossec-control script.
- Fixed compiling issue on Windows.
- Fixed compatibility with Solaris.
- Fixed XML parsing error due to byte stashing issue.
- Fixed false error by Syscheck when creating diff snapshots of empty files.
- Fixed segmentation fault in Authd on i386 platform.
- Fixed agent-auth exit code for controlled server's errors.
- Fixed incorrect OVAL patch results classification.

## [v2.0] - 2017-03-14

### Added

- Wazuh modules manager.
- Wazuh module for OpenSCAP.
- Ruleset for OpenSCAP alerts.
- Kibana dashboards for OpenSCAP.
- Option at agent_control to restart all agents.
- Dynamic fields to rules and decoders.
- Dynamic fields to JSON in alerts/archives.
- CDB list lookup with dynamic fields.
- FTS for dynamic fields.
- Logcollector option to set the frequency of file checking.
- GeoIP support in Alerts (by Scott R Shinn).
- Internal option to output GeoIP data on JSON alerts.
- Matching pattern negation (by Daniel Cid).
- Syscheck and Rootcheck events on SQLite databases.
- Data migration tool to SQLite databases.
- Jenkins QA.
- 64-bit Windows registry keys support.
- Complete FIM data output to JSON and alerts.
- Username, date and inode attributes to FIM events on Unix.
- Username attribute to FIM events on Windows.
- Report changes (FIM file diffs) to Windows agent.
- File diffs to JSON output.
- Elastic mapping updated for new FIM events.
- Title and file fields extracted at Rootcheck alerts.
- Rule description formatting with dynamic field referencing.
- Multithreaded design for Authd server for fast and reliable client dispatching, with key caching and write scheduling.
- Auth registration client for Windows (by Gael Muller).
- Auth password authentication for Windows client.
- New local decoder file by default.
- Show server certificate and key paths at Authd help.
- New option for Authd to verify agent's address.
- Added support for new format at predecoder (by Brad Lhotsky).
- Agentless passlist encoding to Base64.
- New Auditd-specific log format for Logcollector.
- Option for Authd to auto-choose TLS/SSL method.
- Compile option for Authd to make it compatible with legacy OSs.
- Added new templates layout to auto-compose configuration file.
- New wodle for SQLite database syncing (agent information and fim/pm data).
- Added XML settings options to exclude some rules or decoders files.
- Option for agent_control to broadcast AR on all agents.
- Extended FIM event information forwarded by csyslogd (by Sivakumar Nellurandi).
- Report Syscheck's new file events on real time.

### Changed

- Isolated logtest directory from analysisd.
- Remoted informs Analysisd about agent ID.
- Updated Kibana dashboards.
- Syscheck FIM attributes to dynamic fields.
- Force services to exit if PID file creation fails.
- Atomic writing of client.keys through temporary files.
- Disabled remote message ID verification by default.
- Show actual IP on debug message when agents get connected.
- Enforce rules IDs to max 6 digits.
- OSSEC users and group as system (UI-hidden) users (by Dennis Golden).
- Increases Authd connection pool size.
- Use general-purpose version-flexible SSL/TLS methods for Authd registration.
- Enforce minimum 3-digit agent ID format.
- Exclude BTRFS from Rootcheck searching for hidden files inside directories (by Stephan Joerrens).
- Moved OSSEC and Wazuh decoders to one directory.
- Prevent manage_agents from doing invalid actions (such methods for manager at agent).
- Disabled capturing of security events 5145 and 5156 on Windows agent.
- Utilities to rename an agent or change the IP address (by Antonio Querubin).
- Added quiet option for Logtest (by Dan Parriott).
- Output decoder information onto JSON alerts.
- Enable mail notifications by default for server installation.
- Agent control option to restart all agents' Syscheck will also restart manager's Syscheck.
- Make ossec-control to check Authd PID.
- Enforce every rule to contain a description.
- JSON output won't contain field "agentip" if tis value is "any".
- Don't broadcast Active Response messages to disconnected agents.
- Don't print Syscheck logs if it's disabled.
- Set default Syscheck and Rootcheck frequency to 12 hours.
- Generate FIM new file alert by default.
- Added option for Integrator to set the maximum log length.
- JSON output nested objects modelling through dynamic fields.
- Disable TCP for unsupported OSs.
- Show previous log on JSON alert.
- Removed confirmation prompt when importing an agent key successfully.
- Made Syscheck not to ignore files that change more than 3 times by default.
- Enabled JSON output by default.
- Updated default syscheck configuration for Windows agents.
- Limited agent' maximum connection time for notification time.
- Improved client.keys changing detection method by remoted: use date and inode.
- Changed boot service name to Wazuh.
- Active response enabled on Windows agents by default.
- New folder structure for rules and decoders.
- More descriptive logs about syscheck real-time monitoring.
- Renamed XML tags related to rules and decoders inclusion.
- Set default maximum agents to 8000.
- Removed FTS numeric bitfield from JSON output.
- Fixed ID misassignment by manage_agents when the greatest ID exceeds 32512.
- Run Windows Registry Syscheck scan on first stage when scan_on_start enabled.
- Set all Syscheck delay stages to a multiple of internal_options.conf/syscheck.sleep value.
- Changed JSON timestamp format to ISO8601.
- Overwrite @timestamp field from Logstash with the alert timestamp.
- Moved timestamp JSON field to the beginning of the object.
- Changed random data generator for a secure OS-provided generator.

### Fixed

- Logcollector bug that inhibited alerts about file reduction.
- Memory issue on string manipulation at JSON.
- Memory bug at JSON alerts.
- Fixed some CLang warnings.
- Issue on marching OSSEC user on installing.
- Memory leaks at configuration.
- Memory leaks at Analysisd.
- Bugs and memory errors at agent management.
- Mistake with incorrect name for PID file (by Tickhon Clearscale).
- Agent-auth name at messages (it appeared to be the server).
- Avoid Monitord to log errors when the JSON alerts file doesn't exists.
- Agents numbering issue (minimum 3 digits).
- Avoid no-JSON message at agent_control when client.keys empty.
- Memory leaks at manage_agents.
- Authd error messages about connection to queue passed to warning.
- Issue with Authd password checking.
- Avoid ossec-control to use Dash.
- Fixed false error about disconnected agent when trying to send it the shared files.
- Avoid Authd to close when it reaches the maximum concurrency.
- Fixed memory bug at event diff execution.
- Fixed resource leak at file operations.
- Hide help message by useadd and groupadd on OpenBSD.
- Fixed error that made Analysisd to crash if it received a missing FIM file entry.
- Fixed compile warnings at cJSON library.
- Fixed bug that made Active Response to disable all commands if one of them was disabled (by Jason Thomas).
- Fixed segmentation fault at logtest (by Dan Parriott).
- Fixed SQL injection vulnerability at Database.
- Fixed Active Response scripts for Slack and Twitter.
- Fixed potential segmentation fault at file queue operation.
- Fixed file permissions.
- Fixed failing test for Apache 2.2 logs (by Brad Lhotsky).
- Fixed memory error at net test.
- Limit agent waiting time for retrying to connect.
- Fixed compile warnings on i386 architecture.
- Fixed Monitord crash when sending daily report email.
- Fixed script to null route an IP address on Windows Server 2012+ (by Theresa Meiksner).
- Fixed memory leak at Logtest.
- Fixed manager with TCP support on FreeBSD (by Dave Stoddard).
- Fixed Integrator launching at local-mode installation.
- Fixed issue on previous alerts counter (rules with if_matched_sid option).
- Fixed compile and installing error on Solaris.
- Fixed segmentation fault on syscheck when no configuration is defined.
- Fixed bug that prevented manage_agents from removing syscheck/rootcheck database.
- Fixed bug that made agents connected on TCP to hang if they are rejected by the manager.
- Fixed segmentation fault on remoted due to race condition on managing keystore.
- Fixed data lossing at remoted when reloading keystore.
- Fixed compile issue on MacOS.
- Fixed version reading at ruleset updater.
- Fixed detection of BSD.
- Fixed memory leak (by Byron Golden).
- Fixed misinterpretation of octal permissions given by Agentless (by Stephan Leemburg).
- Fixed mistake incorrect openssl flag at Makefile (by Stephan Leemburg).
- Silence Slack integration transmission messages (by Dan Parriott).
- Fixed OpenSUSE Systemd misconfiguration (By Stephan Joerrens).
- Fixed case issue on JSON output for Rootcheck alerts.
- Fixed potential issue on duplicated agent ID detection.
- Fixed issue when creating agent backups.
- Fixed hanging problem on Windows Auth client when negotiation issues.
- Fixed bug at ossec-remoted that mismatched agent-info files.
- Fixed resource leaks at rules configuration parsing.
- Fixed memory leaks at rules parser.
- Fixed memory leaks at XML decoders parser.
- Fixed TOCTOU condition when removing directories recursively.
- Fixed insecure temporary file creation for old POSIX specifications.
- Fixed missing agentless devices identification at JSON alerts.

### Removed

- Deleted link to LUA sources.
- Delete ZLib generated files on cleaning.
- Removed maximum lines limit from diff messages (that remain limited by length).

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

- RESTful API no longer included in extensions/api folder. Available now at https://github.com/wazuh/wazuh-api


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
