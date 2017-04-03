# Change Log
All notable changes to this project will be documented in this file.

## [v2.0]

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
- Exclude BTRFS from Rootcheck searching for hidden files inside directories (by Stehpan Joerrens).
- Moved OSSEC and Wazuh decoders to one directory.
- Prevent manage_agents from doing invalid actions (such methods for manager at agent).
- Disabled capturing of security events 5145 and 5156 on Windows agent.
- Utilities to rename an agent or change the IP address (by Antonio Querubin).
- Added quiet option for Logtest (by Dan Parriot).
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
- Fixed ID misasignation by manage_agents when the gratest ID exceeds 32512.
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
- Agents numberig issue (minimum 3 digits).
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
- Fixed segmentation fault at logtest (by Dan Parriot).
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
- Silence Slack integration transmission messages (by Dan Parriot).
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
