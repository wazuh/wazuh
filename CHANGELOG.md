# Change Log
All notable changes to this project will be documented in this file.

## [v4.10.2]

### Manager

#### Added

- Added new compilation flags for the Vulnerability Detector module. ([#26652](https://github.com/wazuh/wazuh/pull/26652))  

#### Fixed

- Fixed inconsistent vulnerability severity categorization by correcting CVSS version prioritization. ([#26720](https://github.com/wazuh/wazuh/pull/26720))  
- Fixed a potential crash in Wazuh-DB by improving the PID parsing method. ([#26769](https://github.com/wazuh/wazuh/pull/26769))  

### Agent

#### Added

- Improved Syscollector hotfix coverage on Windows by integrating WMI and WUA APIs. ([#26706](https://github.com/wazuh/wazuh/pull/26706))
- Extended Syscollector capabilities to detect installed .pkg packages. ([#26782](https://github.com/wazuh/wazuh/pull/26782))

#### Changed

- Updated standard Python and NPM package location in Syscollector to align with common installation paths. ([#26236](https://github.com/wazuh/wazuh/pull/26236))

### Agent

#### Added

- Support remote (WPK) agent upgrade on arm64 macOS. ([#18545](https://github.com/wazuh/wazuh/pull/18545))

#### Fixed

- Fixed a bug that might make wazuh-modulesd crash on startup. ([#26647](https://github.com/wazuh/wazuh/pull/26647))
- Fixed invalid UTF-8 character checking in FIM. Thanks to @zbalkan. ([#26289](https://github.com/wazuh/wazuh/pull/26289))
- Improved URL validations in Maltiverse Integration. ([#27100](https://github.com/wazuh/wazuh/pull/27100))

### Ruleset

#### Added

- Added SCA content for Windows Server 2025. ([#26732](https://github.com/wazuh/wazuh/issues/26732))
- Added SCA content for Fedora 41. ([#26736](https://github.com/wazuh/wazuh/issues/26736))
- Create SCA policy for Distribution Independent Linux. ([#26837](https://github.com/wazuh/wazuh/issues/26837))
- Create SCA policy for Ubuntu 24.04 LTS. ([#23194](https://github.com/wazuh/wazuh/issues/23194))

#### Changed

- SCA rule Improvement for MacOS 15 SCA. ([#26982](https://github.com/wazuh/wazuh/issues/26982))


## [v4.10.1]

### Manager  

#### Fixed  
- Fixed integration tests for Remoted to ensure proper execution. ([#25939](https://github.com/wazuh/wazuh/pull/25939))  
- Enabled inventory synchronization in Vulnerability Detector when the Indexer module is disabled. ([#26132](https://github.com/wazuh/wazuh/pull/26132))  
- Fixed concurrent access errors in the Vulnerability Detector's OS scan column family. ([#26378](https://github.com/wazuh/wazuh/pull/26378))  

### Agent

#### Added

- Improved Syscollector hotfix coverage on Windows by integrating WMI and WUA APIs. ([#26706](https://github.com/wazuh/wazuh/pull/26706))
- Extended Syscollector capabilities to detect installed .pkg packages. ([#26782](https://github.com/wazuh/wazuh/pull/26782))

#### Changed

- Updated standard Python and NPM package location in Syscollector to align with common installation paths. ([#26236](https://github.com/wazuh/wazuh/pull/26236))


## [v4.10.0]

### Manager

#### Fixed
- Added support for multiple Certificate Authorities files in the indexer connector. ([#24620](https://github.com/wazuh/wazuh/pull/24620))
- Removed hardcoded cipher text size from the RSA decryption method. ([#24529](https://github.com/wazuh/wazuh/pull/24529))
- Avoid infinite loop while updating the vulnerability detector content. ([#25094](https://github.com/wazuh/wazuh/pull/25094))
- Fixed repeated OS vulnerability reports. ([#26223](https://github.com/wazuh/wazuh/pull/26223))
- Fixed inconsistencies between reported context and vulnerability data. ([#25479](https://github.com/wazuh/wazuh/issues/25479))
- Fixed concurrency issues in LRU caches ([#26073](https://github.com/wazuh/wazuh/pull/26073))
- Removed all CVEs related to a deleted agent from the indexer. ([#26232](https://github.com/wazuh/wazuh/pull/26232))
- Prevented an infinite loop when indexing events in the Vulnerability Detector. ([#26922](https://github.com/wazuh/wazuh/pull/26922))
- Fixed segmentation fault in `DescriptionsHelper::vulnerabilityDescription`. ([#26842](https://github.com/wazuh/wazuh/pull/26842))
- Fixed vulnerability scanner re-scan triggers in cluster environment. ([#24034](https://github.com/wazuh/wazuh/pull/24034))
- Fixed an issue where elements in the delayed list were not purged when changing nodes. ([#27145](https://github.com/wazuh/wazuh/pull/27145))
- Added logic to avoid re-scanning disconnected agents. ([#27145](https://github.com/wazuh/wazuh/pull/27145))

#### Changed
- Added self-recovery mechanism for rocksDB databases. ([#24333](https://github.com/wazuh/wazuh/pull/24333))
- Improve logging for indexer connector monitoring class. ([#25189](https://github.com/wazuh/wazuh/pull/25189))
- Added generation of debug symbols. ([#23760](https://github.com/wazuh/wazuh/pull/23760))
- Updated CURL version to 8.10.0. ([#23266](https://github.com/wazuh/wazuh/issues/23266))

### Agent

#### Fixed
- Fixed macOS agent upgrade timeout. ([#25452](https://github.com/wazuh/wazuh/pull/25452))
- Fixed macOS agent startup error by properly redirecting cat command errors in wazuh-control. ([#24531](https://github.com/wazuh/wazuh/pull/24531))
- Fixed inconsistent package inventory size information in Syscollector across operating systems ([#24516](https://github.com/wazuh/wazuh/pull/24516))
- Fixed missing Python path locations for macOS in Data Provider. ([#24125](https://github.com/wazuh/wazuh/pull/24125))
- Fixed permission error on Windows 11 agents after remote upgrade. ([#25429](https://github.com/wazuh/wazuh/pull/25429))
- Fixed increase of the variable containing file size in FIM for Windows. ([#24387](https://github.com/wazuh/wazuh/pull/24387))
- Fixed timeout issue when upgrading Windows agent via WPK. ([#25699](https://github.com/wazuh/wazuh/pull/25699))
- Allowed unknown syslog identifiers in Logcollector's journald reader. ([#26748](https://github.com/wazuh/wazuh/pull/26748))
- Prevented agent termination during package upgrades in containers by removing redundant kill commands. ([#26828](https://github.com/wazuh/wazuh/pull/26828))
- Fixed handle leak in FIM's realtime mode on Windows. ([#26861](https://github.com/wazuh/wazuh/pull/26861))
- Fixed errors on AIX 7.2 by adapting the blibpath variable. ([#26900](https://github.com/wazuh/wazuh/pull/26900))
- Sanitized agent paths to prevent issues with parent folder references. ([#26944](https://github.com/wazuh/wazuh/pull/26944))
- Fixed an issue in the DEB package that prevented the agent from restarting after an upgrade. ([#26633](https://github.com/wazuh/wazuh/pull/26633))
- Improved file path handling in agent communications to avoid references to parent folders. ([#26944](https://github.com/wazuh/wazuh/pull/26944))  
- Set RPM package vendor to `UNKNOWN_VALUE` when the value is missing. ([#27054](https://github.com/wazuh/wazuh/pull/27054))  
- Updated Solaris package generation to use the correct `wazuh-packages` reference. ([#27059](https://github.com/wazuh/wazuh/issues/27059))  

#### Changed
- Added generation of debug symbols. ([#23760](https://github.com/wazuh/wazuh/pull/23760))
- Changed how the AWS module handles non-existent regions. ([#23998](https://github.com/wazuh/wazuh/pull/23998))
- Changed macOS packages building tool. ([#2006](https://github.com/wazuh/wazuh-packages/issues/2006))
- Enhance Wazuh macOS agent installation instructions ([#7498](https://github.com/wazuh/wazuh-documentation/pull/7498))
- Enhance Windows agent signing procedure. ([#2826](https://github.com/wazuh/wazuh-packages/issues/2826))
- Enhance security by implementing a mechanism to prevent unauthorized uninstallation of Wazuh agent on Linux endpoints. ([#23466](https://github.com/wazuh/wazuh/issues/23466))
- Enhance integration with Microsoft Intune MDM to pull audit logs for security alert generation. ([#24498](https://github.com/wazuh/wazuh/issues/24498))
- Updated rootcheck old signatures. ([#26137](https://github.com/wazuh/wazuh/issues/26137))

### RESTful API

#### Added
- Created new endpoint for agent uninstall process. ([#24621](https://github.com/wazuh/wazuh/pull/24621))

### Other

#### Changed
- Updated the embedded Python version up to 3.10.15. ([#25374](https://github.com/wazuh/wazuh/issues/25374))
- Upgraded `certifi` and removed unused packages. ([#25324](https://github.com/wazuh/wazuh/pull/25324))
- Upgraded external `cryptography` library dependency version to 43.0.1. ([#25893](https://github.com/wazuh/wazuh/pull/25893))
- Upgraded external `starlette` and `uvicorn` dependencies. ([#26252](https://github.com/wazuh/wazuh/pull/26252))

### Ruleset

#### Added
- Create SCA Policy for Windows Server 2012 (non R2). ([#21794](https://github.com/wazuh/wazuh/pull/21794))

#### Changed
- Rework SCA Policy for Windows Server 2019. ([#21434](https://github.com/wazuh/wazuh/pull/21434))
- Rework SCA Policy for Red Hat Enterprise Linux 9. ([#24667](https://github.com/wazuh/wazuh/pull/24667))
- Rework SCA Policy for Microsoft Windows Server 2012 R2. ([#24991](https://github.com/wazuh/wazuh/pull/24991))
- Rework SCA Policy for Ubuntu Linux 18.04 LTS. Fix incorrect checks in Ubuntu 22.04 LTS. ([#24957](https://github.com/wazuh/wazuh/pull/24957))
- Rework SCA Policy for Amazon Linux 2 SCA. ([#24969](https://github.com/wazuh/wazuh/pull/24969))
- Rework SCA for SUSE Linux Enterprise 15 SCA. ([#24975](https://github.com/wazuh/wazuh/pull/24975))
- Rework SCA Policy for Apple macOS 13.0 Ventura. ([#24992](https://github.com/wazuh/wazuh/pull/24992))
- Rework SCA Policy for Microsoft Windows 11 Enterprise. ([#25710](https://github.com/wazuh/wazuh/pull/25710))

#### Fixed
- Fixed Logical errors in Windows Server 2022 SCA checks. ([#22597](https://github.com/wazuh/wazuh/pull/22597))
- Fixed wrong regulatory compliance in several Windows rules. ([#25224](https://github.com/wazuh/wazuh/pull/25224))
- Fixed incorrect checks in Ubuntu 22.04 LTS. ([#24733](https://github.com/wazuh/wazuh/pull/24733))
- Removal of check with high CPU utilization in multiple SCA. ([#25190](https://github.com/wazuh/wazuh/pull/25190))


## [v4.9.2]

### Manager

#### Fixed

- Fixed an unhandled exception during IPC event parsing. ([#26453](https://github.com/wazuh/wazuh/pull/26453))


## [v4.9.1]

### Manager

#### Fixed

- Fixed vulnerability detector issue where RPM upgrade wouldn't download new content. ([#24909](https://github.com/wazuh/wazuh/pull/24909))
- Fixed uncaught exception at Keystore test tool. ([#25667](https://github.com/wazuh/wazuh/pull/25667))
- Replaced `eval` calls with `ast.literal_eval`. ([#25705](https://github.com/wazuh/wazuh/pull/25705))
- Fixed the cluster being disabled by default when loading configurations. ([#26277](https://github.com/wazuh/wazuh/pull/26277))
- Added support ARM packages for wazuh-manager. ([#25945](https://github.com/wazuh/wazuh/pull/25945))

#### Changed

- Improved provisioning method for wazuh-keystore to enhance security. ([#24110](https://github.com/wazuh/wazuh/issues/24110))

### Agent

#### Added

- Added support for macOS 15 "Sequoia" in Wazuh Agent. ([#25652](https://github.com/wazuh/wazuh/issues/25652))

#### Fixed

- Fixed agent crash on Windows version 4.8.0. ([#24910](https://github.com/wazuh/wazuh/pull/24910))
- Fixed data race conditions at FIM's `run_check`. ([#25209](https://github.com/wazuh/wazuh/pull/25209))
- Fixed Windows agent crashes related to `syscollector.dll`. ([#24376](https://github.com/wazuh/wazuh/issues/24376))
- Fixed errors related to 'libatomic.a' library on AIX 7.X. ([#25445](https://github.com/wazuh/wazuh/pull/25445))
- Fixed errors in Windows Agent: `EvtFormatMessage` returned errors 15027 and 15033. ([#24932](https://github.com/wazuh/wazuh/pull/24932))
- Fixed FIM issue where it couldn't fetch group entries longer than 1024 bytes. ([#25459](https://github.com/wazuh/wazuh/pull/25459))
- Fixed Wazuh Agent crash at `syscollector`. ([#25469](https://github.com/wazuh/wazuh/pull/25469))
- Fixed a bug in the processed dates in the AWS module related to the AWS Config type. ([#23528](https://github.com/wazuh/wazuh/pull/23528))
- Fixed an error in Custom Logs Buckets when parsing a CSV file that exceeds a certain size. ([#24694](https://github.com/wazuh/wazuh/pull/24694))
- Fixed macOS syslog and ULS not configured out-of-the-box. ([#26108](https://github.com/wazuh/wazuh/issues/26108))

### RESTful API

#### Fixed

- Fixed requests logging to obtain the hash_auth_context from JWT tokens. ([#25764](https://github.com/wazuh/wazuh/pull/25764)) 
- Enabled API to listen IPV4 and IPV6 stacks. ([#25216](https://github.com/wazuh/wazuh/pull/25216))

#### Changed

- Changed the error status code thrown when basic services are down to 500. ([#26103](https://github.com/wazuh/wazuh/pull/26103))


## [v4.9.0]

### Manager

#### Added

- The manager now supports alert forwarding to Fluentd. ([#17306](https://github.com/wazuh/wazuh/pull/17306))
- Added missing functionality for vulnerability scanner translations. ([#23518](https://github.com/wazuh/wazuh/issues/23518))
- Improved performance for vulnerability scanner translations. ([#23722](https://github.com/wazuh/wazuh/pull/23722))
- Enhanced vulnerability scanner logging to be more expressive. ([#24536](https://github.com/wazuh/wazuh/pull/24536))
- Added the HAProxy helper to manage load balancer configuration and automatically balance agents. ([#23513](https://github.com/wazuh/wazuh/pull/23513))
- Added a validation to avoid killing processes from external services. ([#23222](https://github.com/wazuh/wazuh/pull/23222))
- Enabled ceritificates validation in the requests to the HAProxy helper using the default CA bundle. ([#23996](https://github.com/wazuh/wazuh/pull/23996))

#### Fixed

- Fixed compilation issue for local installation. ([#20505](https://github.com/wazuh/wazuh/pull/20505))
- Fixed malformed JSON error in wazuh-analysisd. ([#16666](https://github.com/wazuh/wazuh/pull/16666))
- Fixed a warning when uninstalling the Wazuh manager if the VD feed is missing. ([#24375](https://github.com/wazuh/wazuh/pull/24375))
- Ensured vulnerability detection scanner log messages end with a period. ([#24393](https://github.com/wazuh/wazuh/pull/24393))

#### Changed

- Changed error messages about `recv()` messages from wazuh-db to debug logs. ([#20285](https://github.com/wazuh/wazuh/pull/20285))
- Sanitized the `integrations` directory code. ([#21195](https://github.com/wazuh/wazuh/pull/21195))

### Agent

#### Added

- Added debug logging in FIM to detect invalid report change registry values. Thanks to Zafer Balkan (@zbalkan). ([#21690](https://github.com/wazuh/wazuh/pull/21690))
- Added Amazon Linux 1 and 2023 support for the installation script. ([#21287](https://github.com/wazuh/wazuh/pull/21287))
- Added Journald support in Logcollector. ([#23137](https://github.com/wazuh/wazuh/pull/23137))
- Added support for Amazon Security Hub via AWS SQS. ([#23203](https://github.com/wazuh/wazuh/pull/23203))

#### Fixed

- Fixed loading of whodata through timeouts and retries. ([#21455](https://github.com/wazuh/wazuh/pull/21455))
- Avoided backup failures during WPK update by adding dependency checking for the tar package. ([#21729](https://github.com/wazuh/wazuh/pull/21729))
- Fixed a crash in the agent due to a library incompatibility. ([#22210](https://github.com/wazuh/wazuh/pull/22210))
- Fixed an error in the osquery integration on Windows that avoided loading osquery.conf. ([#21728](https://github.com/wazuh/wazuh/pull/21728))
- Fixed a crash in the agent's Rootcheck component when using `<ignore>`. ([#22588](https://github.com/wazuh/wazuh/pull/22588))
- Fixed command wodle to support UTF-8 characters on windows agent. ([#19146](https://github.com/wazuh/wazuh/pull/19146))
- Fixed Windows agent to delete wazuh-agent.state file when stopped. ([#20425](https://github.com/wazuh/wazuh/pull/20425))
- Fixed Windows Agent 4.8.0 permission errors on Windows 11 after upgrade. ([#20727](https://github.com/wazuh/wazuh/pull/20727))
- Fixed alerts are created when syscheck diff DB is full. ([#16487](https://github.com/wazuh/wazuh/pull/16487))
- Fixed Wazuh deb uninstallation to remove non-config files. ([#2195](https://github.com/wazuh/wazuh-packages/issues/2195))
- Fixed improper Windows agent ACL on non-default installation directory. ([#23273](https://github.com/wazuh/wazuh/pull/23273))
- Fixed socket configuration of an agent is displayed. ([#17664](https://github.com/wazuh/wazuh/pull/17664))
- Fixed wazuh-modulesd printing child process not found error. ([#18494](https://github.com/wazuh/wazuh/pull/18494))
- Fixed issue with an agent starting automatically without reason. ([#23848](https://github.com/wazuh/wazuh/pull/23848))
- Fixed GET /syscheck to properly report size for files larger than 2GB. ([#17415](https://github.com/wazuh/wazuh/pull/17415))
- Fixed error in packages generation centos 7. ([#24412](https://github.com/wazuh/wazuh/pull/24412))
- Fixed Wazuh deb uninstallation to remove non-config files from the installation directory. ([#2195](https://github.com/wazuh/wazuh/issues/2195))
- Fixed Azure auditLogs/signIns status parsing (thanks to @Jmnis for the contribution). ([#22392](https://github.com/wazuh/wazuh/pull/22392))
- Fixed how the S3 object keys with special characters are handled in the Custom Logs Buckets integration. ([#22621](https://github.com/wazuh/wazuh/pull/22621))

#### Changed

- The directory /boot has been removed from the default FIM settings for AIX. ([#19753](https://github.com/wazuh/wazuh/pull/19753))
- Refactored and modularized the Azure integration code. ([#20624](https://github.com/wazuh/wazuh/pull/20624))
- Improved logging of errors in Azure and AWS modules. ([#16314](https://github.com/wazuh/wazuh/issues/16314))

#### Removed

- Dropped support for Python 3.7 in cloud integrations. ([#22583](https://github.com/wazuh/wazuh/pull/22583))

### RESTful API

#### Added

- Added support in the Wazuh API to parse `journald` configurations from the `ossec.conf` file. ([#23094](https://github.com/wazuh/wazuh/pull/23094))
- Added user-agent to the CTI service request. ([#24360](https://github.com/wazuh/wazuh/pull/24360))

#### Changed

- Merged group files endpoints into one (`GET /groups/{group_id}/files/{filename}`) that uses the `raw` parameter to receive plain text data. ([#21653](https://github.com/wazuh/wazuh/pull/21653))
- Removed the hardcoded fields returned by the `GET /agents/outdated` endpoint and added the select parameter to the specification. ([#22388](https://github.com/wazuh/wazuh/pull/22388))
- Updated the regex used to validate CDB lists. ([#22423](https://github.com/wazuh/wazuh/pull/22423))
- Changed the default value for empty fields in the `GET /agents/stats/distinct` endpoint response. ([#22413](https://github.com/wazuh/wazuh/pull/22413))
- Changed the Wazuh API endpoint responses when receiving the `Expect` header. ([#22380](https://github.com/wazuh/wazuh/pull/22380))
- Enhanced Authorization header values decoding errors to avoid showing the stack trace and fail gracefully. ([#22745](https://github.com/wazuh/wazuh/pull/22745))
- Updated the format of the fields that can be N/A in the API specification. ([#22908](https://github.com/wazuh/wazuh/pull/22908))
- Updated the WAZUH API specification to conform with the current endpoint requests and responses. ([#22954](https://github.com/wazuh/wazuh/pull/22954))
- Replaced the used aiohttp server with uvicorn. ([#23199](https://github.com/wazuh/wazuh/pull/23199))
    - Changed the `PUT /groups/{group_id}/configuration` endpoint response error code when uploading an empty file.
    - Changed the `GET, PUT and DELETE /lists/files/{filename}` endpoints response status code when an invalid file is used.
    - Changed the `PUT /manager/configuration` endpoint response status code when uploading a file with invalid content-type.

#### Fixed

- Improved XML validation to match the Wazuh internal XML validator. ([#20507](https://github.com/wazuh/wazuh/pull/20507))
- Fixed bug in `GET /groups`. ([#22428](https://github.com/wazuh/wazuh/pull/22428))
- Fixed the `GET /agents/outdated` endpoint query. ([#24946](https://github.com/wazuh/wazuh/pull/24946))

#### Removed

- Removed the `cache` configuration option from the Wazuh API. ([#22416](https://github.com/wazuh/wazuh/pull/22416))

### Ruleset

#### Changed

- The solved vulnerability rule has been clarified. ([#19754](https://github.com/wazuh/wazuh/pull/19754))

#### Fixed

- Fixed audit decoders to parse the new heading field "node=". ([#22178](https://github.com/wazuh/wazuh/pull/22178))

### Other

#### Changed

- Upgraded external OpenSSL library dependency version to 3.0. ([#20778](https://github.com/wazuh/wazuh/pull/20778))
- Migrated QA framework. ([#17427](https://github.com/wazuh/wazuh/issues/17427))
- Improved WPKs. ([#21152](https://github.com/wazuh/wazuh/issues/21152))
- Migrated and adapted Wazuh subsystem repositories as part of Wazuh packages redesign. ([#23508](https://github.com/wazuh/wazuh/pull/23508))
- Upgraded external connexion library dependency version to 3.0.5 and its related interdependencies. ([#22680](https://github.com/wazuh/wazuh/pull/22680))

#### Fixed

- Fixed a buffer overflow hazard in HMAC internal library. ([#19794](https://github.com/wazuh/wazuh/pull/19794))


## [v4.8.2]

### Manager

#### Fixed

- Fixed memory management in wazuh-remoted that might cause data corruption in incoming messages. ([#25225](https://github.com/wazuh/wazuh/issues/25225))


## [v4.8.1]

### Manager

#### Added

- Added dedicated RSA keys for keystore encryption. ([#24357](https://github.com/wazuh/wazuh/pull/24357))

#### Fixed

- Fixed bug in `upgrade_agent` CLI where it would sometimes raise an unhandled exception. ([#24341](https://github.com/wazuh/wazuh/pull/24341))
- Changed keystore cipher algorithm to remove reuse of sslmanager.cert and sslmanager.key. ([#24509](https://github.com/wazuh/wazuh/pull/24509))

### Agent

#### Fixed

- Fixed incorrect macOS agent name retrieval. ([#23989](https://github.com/wazuh/wazuh/pull/23989))

### RESTful API

#### Changed

- Changed `GET /manager/version/check` endpoint response to always show the `uuid` field. ([#24173](https://github.com/wazuh/wazuh/pull/24173))

### Other

#### Changed

- Upgraded external Jinja2 library dependency version to 3.1.4. ([#24108](https://github.com/wazuh/wazuh/pull/24108))
- Upgraded external requests library dependency version to 2.32.2. ([#23925](https://github.com/wazuh/wazuh/pull/23925))


## [v4.8.0]

### Manager

#### Added

- Transition to Wazuh Keystore for Indexer Configuration. ([#21670](https://github.com/wazuh/wazuh/pull/21670))

#### Changed

- Vulnerability Detection refactor. ([#21201](https://github.com/wazuh/wazuh/pull/21201))
- Improved wazuh-db detection of deleted database files. ([#18476](https://github.com/wazuh/wazuh/pull/18476))
- Added timeout and retry parameters to the VirusTotal integration. ([#16893](https://github.com/wazuh/wazuh/pull/16893))
- Extended wazuh-analysisd EPS metrics with events dropped by overload and remaining credits in the previous cycle. ([#18988](https://github.com/wazuh/wazuh/pull/18988))
- Updated API and framework packages installation commands to use pip instead of direct invocation of setuptools. ([#18466](https://github.com/wazuh/wazuh/pull/18466))
- Upgraded docker-compose V1 to V2 in API Integration test scripts. ([#17750](https://github.com/wazuh/wazuh/pull/17750))
- Refactored how cluster status dates are treated in the cluster. ([#17015](https://github.com/wazuh/wazuh/pull/17015))
- The log message about file rotation and signature from wazuh-monitord has been updated. ([#21602](https://github.com/wazuh/wazuh/pull/21602))
- Improved Wazuh-DB performance by adjusting SQLite synchronization policy. ([#22774](https://github.com/wazuh/wazuh/pull/22774))

#### Fixed

- Updated cluster connection cleanup to remove temporary files when the connection between a worker and a master is broken. ([#17886](https://github.com/wazuh/wazuh/pull/17886))
- Added a mechanism to avoid cluster errors to raise from expected wazuh-db exceptions. ([#23371](https://github.com/wazuh/wazuh/pull/23371))
- Fixed race condition when creating agent database files from a template. ([#23216](https://github.com/wazuh/wazuh/pull/23216))

### Agent

#### Added

- Added snap package manager support to Syscollector. ([#15740](https://github.com/wazuh/wazuh/pull/15740))
- Added event size validation for the external integrations. ([#17932](https://github.com/wazuh/wazuh/pull/17932))
- Added new unit tests for the AWS integration. ([#17623](https://github.com/wazuh/wazuh/pull/17623))
- Added mapping geolocation for AWS WAF integration. ([#20649](https://github.com/wazuh/wazuh/pull/20649))
- Added a validation to reject unsupported regions when using the inspector service. ([#21530](https://github.com/wazuh/wazuh/pull/21530))
- Added additional information on some AWS integration errors. ([#21561](https://github.com/wazuh/wazuh/pull/21561))

#### Changed

- Disabled host's IP query by Logcollector when ip_update_interval=0. ([#18574](https://github.com/wazuh/wazuh/pull/18574))
- The MS Graph integration module now supports multiple tenants. ([#19064](https://github.com/wazuh/wazuh/pull/19064))
- FIM now buffers the Linux audit events for who-data to prevent side effects in other components. ([#16200](https://github.com/wazuh/wazuh/pull/16200))
- The sub-process execution implementation has been improved. ([#19720](https://github.com/wazuh/wazuh/pull/19720))
- Refactored and modularized the AWS integration code. ([#17623](https://github.com/wazuh/wazuh/pull/17623))
- Replace the usage of fopen with wfopen to avoid processing invalid characters on Windows. ([#21791](https://github.com/wazuh/wazuh/pull/21791))
- Prevent macOS agent to start automatically after installation. ([#21637](https://github.com/wazuh/wazuh/pull/21637))

#### Fixed

- Fixed process path retrieval in Syscollector on Windows XP. ([#16839](https://github.com/wazuh/wazuh/pull/16839))
- Fixed detection of the OS version on Alpine Linux. ([#16056](https://github.com/wazuh/wazuh/pull/16056))
- Fixed Solaris 10 name not showing in the Dashboard. ([#18642](https://github.com/wazuh/wazuh/pull/18642))
- Fixed macOS Ventura compilation from sources. ([#21932](https://github.com/wazuh/wazuh/pull/21932))
- Fixed PyPI package gathering on macOS Sonoma. ([#23532](https://github.com/wazuh/wazuh/pull/23532))

### RESTful API

#### Added

- Added new `GET /manager/version/check` endpoint to obtain information about new releases of Wazuh. ([#19952](https://github.com/wazuh/wazuh/pull/19952))
- Introduced an `auto` option for the ssl_protocol setting in the API configuration. This enables automatic negotiation of the TLS certificate to be used. ([#20420](https://github.com/wazuh/wazuh/pull/20420))
- Added API indexer protection to allow uploading new configuration files if the `<indexer>` section is not modified. ([#22727](https://github.com/wazuh/wazuh/pull/22727))

#### Fixed

- Fixed a warning from SQLAlchemy involving detached Roles instances in RBAC. ([#20527](https://github.com/wazuh/wazuh/pull/20527))
- Fixed an issue where only the last `<ignore>` item was displayed in `GET /manager/configuration`. ([#23095](https://github.com/wazuh/wazuh/issues/23095))

#### Removed

- Removed `PUT /vulnerability`, `GET /vulnerability/{agent_id}`, `GET /vulnerability/{agent_id}/last_scan` and `GET /vulnerability/{agent_id}/summary/{field}` API endpoints as they were deprecated in version 4.7.0. Use the Wazuh indexer REST API instead. ([#20119](https://github.com/wazuh/wazuh/pull/20119))
- Removed the `compilation_date` field from `GET /cluster/{node_id}/info` and `GET /manager/info` endpoints. ([#21572](https://github.com/wazuh/wazuh/pull/21572))
- Deprecated the `cache` configuration option. ([#22387](https://github.com/wazuh/wazuh/pull/22387))
- Removed `custom` parameter from `PUT /active-response` endpoint. ([#17048](https://github.com/wazuh/wazuh/pull/17048))

### Ruleset

#### Added

- Added new SCA policy for Amazon Linux 2023. ([#17780](https://github.com/wazuh/wazuh/pull/17780))
- Added new SCA policy for Rocky Linux 8. ([#17784](https://github.com/wazuh/wazuh/pull/17784))
- Added rules to detect IcedID attacks. ([#19528](https://github.com/wazuh/wazuh/pull/19528))

#### Changed

- SCA policy for Ubuntu Linux 18.04 rework. ([#18721](https://github.com/wazuh/wazuh/pull/18721))
- SCA policy for Ubuntu Linux 22.04 rework. ([#17515](https://github.com/wazuh/wazuh/pull/17515))
- SCA policy for Red Hat Enterprise Linux 7 rework. ([#18440](https://github.com/wazuh/wazuh/pull/18440))
- SCA policy for Red Hat Enterprise Linux 8 rework. ([#17770](https://github.com/wazuh/wazuh/pull/17770))
- SCA policy for Red Hat Enterprise Linux 9 rework. ([#17412](https://github.com/wazuh/wazuh/pull/17412))
- SCA policy for CentOS 7 rework. ([#17624](https://github.com/wazuh/wazuh/pull/17624))
- SCA policy for CentOS 8 rework. ([#18439](https://github.com/wazuh/wazuh/pull/18439))
- SCA policy for Debian 8 rework. ([#18010](https://github.com/wazuh/wazuh/pull/18010))
- SCA policy for Debian 10 rework. ([#17922](https://github.com/wazuh/wazuh/pull/17922))
- SCA policy for Amazon Linux 2 rework. ([#18695](https://github.com/wazuh/wazuh/pull/18695))
- SCA policy for SUSE Linux Enterprise 15 rework. ([#18985](https://github.com/wazuh/wazuh/pull/18985))
- SCA policy for macOS 13.0 Ventura rework. ([#19037](https://github.com/wazuh/wazuh/pull/19037))
- SCA policy for Microsoft Windows 10 Enterprise rework. ([#19515](https://github.com/wazuh/wazuh/pull/19515))
- SCA policy for Microsoft Windows 11 Enterprise rework. ([#20044](https://github.com/wazuh/wazuh/pull/20044))
- Update MITRE DB to v13.1. ([#17518](https://github.com/wazuh/wazuh/pull/17518))

### Other

#### Added

- Added external lua library dependency version 5.3.6. ([#21710](https://github.com/wazuh/wazuh/pull/21710))
- Added external PyJWT library dependency version 2.8.0. ([#21749](https://github.com/wazuh/wazuh/pull/21749))

#### Changed

- Upgraded external aiohttp library dependency version to 3.9.5. ([#23112](https://github.com/wazuh/wazuh/pull/23112))
- Upgraded external idna library dependency version to 3.7. ([#23112](https://github.com/wazuh/wazuh/pull/23112))
- Upgraded external cryptography library dependency version to 42.0.4. ([#22221](https://github.com/wazuh/wazuh/pull/22221))
- Upgraded external numpy library dependency version to 1.26.0. ([#20003](https://github.com/wazuh/wazuh/pull/20003))
- Upgraded external grpcio library dependency version to 1.58.0. ([#20003](https://github.com/wazuh/wazuh/pull/20003))
- Upgraded external pyarrow library dependency version to 14.0.1. ([#20493](https://github.com/wazuh/wazuh/pull/20493))
- Upgraded external urllib3 library dependency version to 1.26.18. ([#20630](https://github.com/wazuh/wazuh/pull/20630))
- Upgraded external SQLAlchemy library dependency version to 2.0.23. ([#20741](https://github.com/wazuh/wazuh/pull/20741))
- Upgraded external Jinja2 library dependency version to 3.1.3. ([#21684](https://github.com/wazuh/wazuh/pull/21684))
- Upgraded embedded Python version to 3.10.13. ([#20003](https://github.com/wazuh/wazuh/pull/20003))
- Upgraded external curl library dependency version to 8.5.0. ([#21710](https://github.com/wazuh/wazuh/pull/21710))
- Upgraded external pcre2 library dependency version to 10.42. ([#21710](https://github.com/wazuh/wazuh/pull/21710))
- Upgraded external libarchive library dependency version to 3.7.2. ([#21710](https://github.com/wazuh/wazuh/pull/21710))
- Upgraded external rpm library dependency version to 4.18.2. ([#21710](https://github.com/wazuh/wazuh/pull/21710))
- Upgraded external sqlite library dependency version to 3.45.0. ([#21710](https://github.com/wazuh/wazuh/pull/21710))
- Upgraded external zlib library dependency version to 1.3.1. ([#21710](https://github.com/wazuh/wazuh/pull/21710))

#### Deleted

- Removed external `python-jose` and `ecdsa` library dependencies. ([#21749](https://github.com/wazuh/wazuh/pull/21749))


## [v4.7.5]

### Manager

#### Added

- Added a database endpoint to recalculate the hash of agent groups. ([#23441](https://github.com/wazuh/wazuh/pull/23441))

#### Fixed

- Fixed an issue in a cluster task where full group synchronization was constantly triggered. ([#23447](https://github.com/wazuh/wazuh/pull/23447))
- Fixed a race condition in wazuh-db that might create corrupted database files. ([#23467](https://github.com/wazuh/wazuh/pull/23467))

### Agent

#### Fixed

- Fixed segmentation fault in logcollector multiline-regex configuration. ([#23468](https://github.com/wazuh/wazuh/pull/23468))
- Fixed crash in fim when processing paths with non UTF-8 characters. ([#23543](https://github.com/wazuh/wazuh/pull/23543))


## [v4.7.4]

### Manager

#### Fixed

- Fixed an issue where wazuh-db was retaining labels of deleted agents. ([#22933](https://github.com/wazuh/wazuh/pull/22933))
- Improved stability by ensuring workers resume normal operations even during master node downtime. ([#22994](https://github.com/wazuh/wazuh/pull/22994))


## [v4.7.3]

### Manager

#### Fixed

- Resolved a transitive mutex locking issue in wazuh-db that was impacting performance. ([#21997](https://github.com/wazuh/wazuh/pull/21997))
- Wazuh DB internal SQL queries have been optimized by tuning database indexes to improve performance. ([#21977](https://github.com/wazuh/wazuh/pull/21977))


## [v4.7.2]

### Manager

#### Added

- Added minimum time constraint of 1 hour for Vulnerability Detector feed downloads. ([#21142](https://github.com/wazuh/wazuh/pull/21142))

#### Fixed

- wazuh-remoted now includes the offending bytes in the warning about invalid message size from agents. ([#21011](https://github.com/wazuh/wazuh/pull/21011))
- Fixed a bug in the Windows Eventchannel decoder on handling Unicode characters. ([#20658](https://github.com/wazuh/wazuh/pull/20658))
- Fixed data validation at Windows Eventchannel decoder. ([#20735](https://github.com/wazuh/wazuh/pull/20735))

### Agent

#### Added

- Added timeouts to external and Cloud integrations to prevent indefinite waiting for a response. ([#20638](https://github.com/wazuh/wazuh/pull/20638))

#### Fixed

- The host_deny Active response now checks the IP parameter format. ([#20656](https://github.com/wazuh/wazuh/pull/20656))
- Fixed a bug in the Windows agent that might lead it to crash when gathering forwarded Windows events. ([#20594](https://github.com/wazuh/wazuh/pull/20594))
- The AWS integration now finds AWS configuration profiles that do not contain the `profile` prefix. ([#20447](https://github.com/wazuh/wazuh/pull/20447))
- Fixed parsing for regions argument of the AWS integration. ([#20660](https://github.com/wazuh/wazuh/pull/20660))

### Ruleset

#### Added

- Added new SCA policy for Debian 12. ([#17565](https://github.com/wazuh/wazuh/pull/17565))

#### Fixed

- Fixed AWS Macie fields used in some rules and removed unused AWS Macie Classic rules. ([#20663](https://github.com/wazuh/wazuh/pull/20663))

### Other

#### Changed

- Upgraded external aiohttp library dependency version to 3.9.1. ([#20798](https://github.com/wazuh/wazuh/pull/20798))
- Upgraded pip dependency version to 23.3.2. ([#20632](https://github.com/wazuh/wazuh/issues/20632))


## [v4.7.1]

### Manager

#### Fixed

- Fixed a bug causing the Canonical feed parser to fail in Vulnerability Detector. ([#20580](https://github.com/wazuh/wazuh/pull/20580))
- Fixed a thread lock bug that slowed down wazuh-db performance. ([#20178](https://github.com/wazuh/wazuh/pull/20178))
- Fixed a bug in Vulnerability detector that skipped vulnerabilities for Windows 11 21H2. ([#20386](https://github.com/wazuh/wazuh/pull/20386))
- The installer now updates the merged.mg file permissions on upgrade. ([#5941](https://github.com/wazuh/wazuh/pull/5941))
- Fixed an insecure request warning in the shuffle integration. ([#19993](https://github.com/wazuh/wazuh/pull/19993))
- Fixed a bug that corrupted cluster logs when they were rotated. ([#19888](https://github.com/wazuh/wazuh/pull/19888))

### Agent

#### Changed

- Improved WPK upgrade scripts to ensure safe execution and backup generation in various circumstances. ([#20616](https://github.com/wazuh/wazuh/pull/20616))

#### Fixed

- Fixed a bug that allowed two simultaneous updates to occur through WPK. ([#20545](https://github.com/wazuh/wazuh/pull/20545))
- Fixed a bug that prevented the local IP from appearing in the port inventory from macOS agents. ([#20332](https://github.com/wazuh/wazuh/pull/20332))
- Fixed the default Logcollector settings on macOS to collect logs out-of-the-box. ([#20180](https://github.com/wazuh/wazuh/pull/20180))
- Fixed a bug in the FIM decoder at wazuh-analysisd that ignored Windows Registry events from agents under 4.6.0. ([#20169](https://github.com/wazuh/wazuh/pull/20169))
- Fixed multiple bugs in the Syscollector decoder at wazuh-analysisd that did not sanitize the input data properly. ([#20250](https://github.com/wazuh/wazuh/pull/20250))
- Added the pyarrow_hotfix dependency to fix the pyarrow CVE-2023-47248 vulnerability in the AWS integration. ([#20284](https://github.com/wazuh/wazuh/pull/20284))

### RESTful API

#### Fixed

- Fixed inconsistencies in the behavior of the `q` parameter of some endpoints. ([#18423](https://github.com/wazuh/wazuh/pull/18423))
- Fixed a bug in the `q` parameter of the `GET /groups/{group_id}/agents` endpoint. ([#18495](https://github.com/wazuh/wazuh/pull/18495))
- Fixed bug in the regular expression used to to reject non ASCII characters in some endpoints. ([#19533](https://github.com/wazuh/wazuh/pull/19533))

### Other

#### Changed

- Upgraded external certifi library dependency version to 2023.07.22. ([#20149](https://github.com/wazuh/wazuh/pull/20149))
- Upgraded external requests library dependency version to 2.31.0. ([#20149](https://github.com/wazuh/wazuh/pull/20149))
- Upgraded embedded Python version to 3.9.18. ([#18800](https://github.com/wazuh/wazuh/issues/18800))

## [v4.7.0]

### Manager

#### Added

- Introduced native Maltiverse integration. Thanks to David Gil (@dgilm). ([#18026](https://github.com/wazuh/wazuh/pull/18026))
- Added a file detailing the dependencies for the Wazuh RESTful API and wodles tests. ([#16513](https://github.com/wazuh/wazuh/pull/16513))
- Added unit tests for the Syscollector legacy decoder. ([#15985](https://github.com/wazuh/wazuh/pull/15985))
- Added unit tests for the manage_agents tool. ([#15999](https://github.com/wazuh/wazuh/pull/15999))
- Added an option to customize the Slack integration. ([#16090](https://github.com/wazuh/wazuh/pull/16090))
- Added support for Amazon Linux 2023 in Vulnerability Detector. ([#17617](https://github.com/wazuh/wazuh/issue/17617))

#### Changed

- An unnecessary sanity check related to Syscollector has been removed from wazuh-db. ([#16008](https://github.com/wazuh/wazuh/pull/16008))
- The manager now rejects agents with a higher version by default. ([#20367](https://github.com/wazuh/wazuh/pull/20367))

#### Fixed

- Fixed an unexpected error by the Cluster when a worker gets restarted. ([#16683](https://github.com/wazuh/wazuh/pull/16683))
- Fixed Syscollector packages multiarch values. ([#19722](https://github.com/wazuh/wazuh/issues/19722))
- Fixed a bug that made the Windows agent crash randomly when loading RPCRT4.dll. ([#18591](https://github.com/wazuh/wazuh/issues/18591))

#### Deleted

- Delete unused framework RBAC migration folder. ([#17225](https://github.com/wazuh/wazuh/pull/17225))

### Agent

#### Added

- Added support for Custom Logs in Buckets via AWS SQS. ([#17951](https://github.com/wazuh/wazuh/pull/17951))
- Added geolocation for `aws.data.client_ip` field. Thanks to @rh0dy. ([#16198](https://github.com/wazuh/wazuh/pull/16198))
- Added package inventory support for Alpine Linux in Syscollector. ([#15699](https://github.com/wazuh/wazuh/pull/15699))
- Added package inventory support for MacPorts in Syscollector. ([#15877](https://github.com/wazuh/wazuh/pull/15877))
- Added package inventory support for PYPI and node in Syscollector. ([#17982](https://github.com/wazuh/wazuh/pull/17982))
- Added related process information to the open ports inventory in Syscollector. ([#15000](https://github.com/wazuh/wazuh/pull/15000))

#### Changed

- The shared modules' code has been sanitized according to the convention. ([#17966](https://github.com/wazuh/wazuh/pull/17966))
- The package inventory internal messages have been modified to honor the schema compliance. ([#18006](https://github.com/wazuh/wazuh/pull/18006))
- The agent connection log has been updated to clarify that the agent must connect to an agent with the same or higher version. ([#20360](https://github.com/wazuh/wazuh/pull/20360))

#### Fixed

- Fixed detection of osquery 5.4.0+ running outside the integration. ([#17006](https://github.com/wazuh/wazuh/pull/17006))
- Fixed vendor data in package inventory for Brew packages on macOS. ([#16089](https://github.com/wazuh/wazuh/pull/16089))
- Fixed WPK rollback restarting host in Windows agent ([#20081](https://github.com/wazuh/wazuh/pull/20081))

### RESTful API

### Added
- Added new `status_code` field to `GET /agents` response. ([#19726](https://github.com/wazuh/wazuh/pull/19726))

#### Fixed

- Addressed error handling for non-utf-8 encoded file readings. ([#16489](https://github.com/wazuh/wazuh/pull/16489))
- Resolved an issue in the `WazuhException` class that disrupted the API executor subprocess. ([#16914](https://github.com/wazuh/wazuh/pull/16914))
- Corrected an empty value problem in the API specification key. ([#16918](https://github.com/wazuh/wazuh/issues/16918))

#### Deleted

- Deprecated `PUT /vulnerability`, `GET /vulnerability/{agent_id}`, `GET /vulnerability/{agent_id}/last_scan` and `GET /vulnerability/{agent_id}/summary/{field}` API endpoints. In future versions, the Wazuh indexer REST API can be used instead. ([#20126](https://github.com/wazuh/wazuh/pull/20126))

### Other

#### Fixed

- Fixed the signature of the internal function `OSHash_GetIndex()`. ([#17040](https://github.com/wazuh/wazuh/pull/17040))

## [v4.6.0]

### Manager

#### Added

- wazuh-authd can now generate X509 certificates. ([#13559](https://github.com/wazuh/wazuh/pull/13559))
- Introduced a new CLI to manage features related to the Wazuh API RBAC resources. ([#13797](https://github.com/wazuh/wazuh/pull/13797))
- Added support for Amazon Linux 2022 in Vulnerability Detector. ([#13034](https://github.com/wazuh/wazuh/issue/13034))
- Added support for Alma Linux in Vulnerability Detector. ([#16343](https://github.com/wazuh/wazuh/pull/16343))
- Added support for Debian 12 in Vulnerability Detector. ([#18542](https://github.com/wazuh/wazuh/pull/18542))
- Added mechanism in wazuh-db to identify fragmentation and perform vacuum. ([#14953](https://github.com/wazuh/wazuh/pull/14953))
- Added an option to set whether the manager should ban newer agents. ([#18333](https://github.com/wazuh/wazuh/pull/18333))
- Added mechanism to prevent wazuh agents connections to lower manager versions. ([#15661](https://github.com/wazuh/wazuh/pull/15661))

#### Changed

- wazuh-remoted now checks the size of the files to avoid malformed merged.mg. ([#14659](https://github.com/wazuh/wazuh/pull/14659))
- Added a limit option for the Rsync dispatch queue size. ([#14024](https://github.com/wazuh/wazuh/pull/14024))
- Added a limit option for the Rsync thread pool. ([#14026](https://github.com/wazuh/wazuh/pull/14026))
- wazuh-authd now shows a warning when deprecated forcing options are present in the configuration. ([#14549](https://github.com/wazuh/wazuh/pull/14549))
- The agent now notifies the manager when Active Reponse fails to run `netsh`. ([#14804](https://github.com/wazuh/wazuh/pull/14804))
- Use new broadcast system to send agent groups information from the master node of a cluster. ([#13906](https://github.com/wazuh/wazuh/pull/13906))
- Changed cluster `send_request` method so that timeouts are treated as exceptions and not as responses. ([#15220](https://github.com/wazuh/wazuh/pull/15220))
- Refactored methods responsible for file synchronization within the cluster. ([#13065](https://github.com/wazuh/wazuh/pull/13065))
- Changed schema constraints for sys_hwinfo table. ([#16065](https://github.com/wazuh/wazuh/pull/16065))
- Auth process not start when registration password is empty. ([#15709](https://github.com/wazuh/wazuh/pull/15709))
- Changed error messages about corrupt GetSecurityInfo messages from FIM to debug logs. ([#19400](https://github.com/wazuh/wazuh/pull/19400))
- Changed the default settings for wazuh-db to perform database auto-vacuum more often. ([#19956](https://github.com/wazuh/wazuh/pull/19956))

#### Fixed

- Fixed wazuh-remoted not updating total bytes sent in UDP. ([#13979](https://github.com/wazuh/wazuh/pull/13979))
- Fixed translation of packages with a missing version in CPE Helper for Vulnerability Detector. ([#14356](https://github.com/wazuh/wazuh/pull/14356))
- Fixed undefined behavior issues in Vulnerability Detector unit tests. ([#14174](https://github.com/wazuh/wazuh/pull/14174))
- Fixed permission error when producing FIM alerts. ([#14019](https://github.com/wazuh/wazuh/pull/14019))
- Fixed memory leaks wazuh-authd. ([#15164](https://github.com/wazuh/wazuh/pull/15164))
- Fixed Audit policy change detection in FIM for Windows. ([#14763](https://github.com/wazuh/wazuh/pull/14763))
- Fixed `origin_module` variable value when sending API or framework messages to core sockets. ([#14408](https://github.com/wazuh/wazuh/pull/14408))
- Fixed an issue where an erroneous tag appeared in the cluster logs. ([#15715](https://github.com/wazuh/wazuh/pull/15715))
- Fixed log error displayed when there's a duplicate worker node name within a cluster. ([#15250](https://github.com/wazuh/wazuh/issues/15250))
- Resolved an issue in the `agent_upgrade` CLI when used from worker nodes. ([#15487](https://github.com/wazuh/wazuh/pull/15487))
- Fixed error in the `agent_upgrade` CLI when displaying upgrade result. ([#18047](https://github.com/wazuh/wazuh/issues/18047))
- Fixed error in which the connection with the cluster was broken in local clients for not sending keepalives messages. ([#15277](https://github.com/wazuh/wazuh/pull/15277))
- Fixed error in which exceptions were not correctly handled when `dapi_err` command could not be sent to peers. ([#15298](https://github.com/wazuh/wazuh/pull/15298))
- Fixed error in worker's Integrity sync task when a group folder was deleted in master. ([#16257](https://github.com/wazuh/wazuh/pull/16257))
- Fixed error when trying tu update an agent through the API or the CLI while pointing to a WPK file. ([#16506](https://github.com/wazuh/wazuh/pull/16506))
- Fixed wazuh-remoted high CPU usage in master node without agents. ([#15074](https://github.com/wazuh/wazuh/pull/15074))
- Fixed race condition in wazuh-analysisd handling rule ignore option. ([#16101](https://github.com/wazuh/wazuh/pull/16101))
- Fixed missing rules and decoders in Analysisd JSON report. ([#16000](https://github.com/wazuh/wazuh/pull/16000))
- Fixed translation of packages with missing version in CPE Helper. ([#14356](https://github.com/wazuh/wazuh/pull/14356))
- Fixed log date parsing at predecoding stage. ([#15826](https://github.com/wazuh/wazuh/pull/15826))
- Fixed permission error in JSON alert. ([#14019](https://github.com/wazuh/wazuh/pull/14019))

### Agent

#### Added

- Added GuardDuty Native support to the AWS integration. ([#15226](https://github.com/wazuh/wazuh/pull/15226))
- Added `--prefix` parameter to Azure Storage integration. ([#14768](https://github.com/wazuh/wazuh/pull/14768))
- Added validations for empty and invalid values in AWS integration. ([#16493](https://github.com/wazuh/wazuh/pull/16493))
- Added new unit tests for GCloud integration and increased coverage to 99%. ([#13573](https://github.com/wazuh/wazuh/pull/13573))
- Added new unit tests for Azure Storage integration and increased coverage to 99%. ([#14104](https://github.com/wazuh/wazuh/pull/14104))
- Added new unit tests for Docker Listener integration. ([#14177](https://github.com/wazuh/wazuh/pull/14177))
- Added support for Microsoft Graph security API. Thanks to Bryce Shurts (@S-Bryce). ([#18116](https://github.com/wazuh/wazuh/pull/18116))
- Added wildcard support in FIM Windows registers. ([#15852](https://github.com/wazuh/wazuh/pull/15852))
- Added wildcards support for folders in the localfile configuration on Windows. ([#15973](https://github.com/wazuh/wazuh/pull/15973))
- Added new settings `ignore` and `restrict` to logcollector. ([#14782](https://github.com/wazuh/wazuh/pull/14782))
- Added RSync and DBSync to FIM. ([#12745](https://github.com/wazuh/wazuh/pull/12745))
- Added PCRE2 regex for SCA policies. ([#17124](https://github.com/wazuh/wazuh/pull/17124))
- Added mechanism to detect policy changes. ([#14763](https://github.com/wazuh/wazuh/pull/14763))
- Added support for Office365 MS/Azure Government Community Cloud (GCC) and Government Community Cloud High (GCCH) API. Thanks to Bryce Shurts (@S-Bryce). ([#16547](https://github.com/wazuh/wazuh/pull/16547))

#### Changed

- FIM option fim_check_ignore now applies to files and directories. ([#13264](https://github.com/wazuh/wazuh/pull/13264))
- Changed AWS integration to take into account user config found in the `.aws/config` file. ([#16531](https://github.com/wazuh/wazuh/pull/16531))
- Changed the calculation of timestamps in AWS and Azure modules by using UTC timezone. ([#14537](https://github.com/wazuh/wazuh/pull/14537))
- Changed the AWS integration to only show the `Skipping file with another prefix` message in debug mode. ([#15009](https://github.com/wazuh/wazuh/pull/15009))
- Changed debug level required to display CloudWatch Logs event messages. ([#14999](https://github.com/wazuh/wazuh/pull/14999))
- Changed syscollector database default permissions. ([#17447](https://github.com/wazuh/wazuh/pull/17447))
- Changed agent IP lookup algorithm. ([#17161](https://github.com/wazuh/wazuh/pull/17161))
- Changed InstallDate origin in windows installed programs. ([#14499](https://github.com/wazuh/wazuh/pull/14499))
- Enhanced clarity of certain error messages in the AWS integration for better exception tracing. ([#14524](https://github.com/wazuh/wazuh/pull/14524))
- Improved external integrations SQLite queries. ([#13420](https://github.com/wazuh/wazuh/pull/13420))
- Improved items iteration for `Config` and `VPCFlow` AWS integrations. ([#16325](https://github.com/wazuh/wazuh/pull/16325))
- Unit tests have been added to the shared JSON handling library. ([#14784](https://github.com/wazuh/wazuh/pull/14784))
- Unit tests have been added to the shared SQLite handling library. ([#14476](https://github.com/wazuh/wazuh/pull/14476))
- Improved command to change user and group from version 4.2.x to 4.x.x. ([#15032](https://github.com/wazuh/wazuh/pull/15032))
- Changed the internal value of the open_attemps configuration. ([#15647](https://github.com/wazuh/wazuh/pull/15647))
- Reduced the default FIM event throughput to 50 EPS. ([#19758](https://github.com/wazuh/wazuh/pull/19758))

#### Fixed

- Fixed the architecture of the dependency URL for macOS. ([#13534](https://github.com/wazuh/wazuh/pull/13534))
- Fixed a path length limitation that prevented FIM from reporting changes on Windows. ([#13588](https://github.com/wazuh/wazuh/pull/13588))
- Updated the AWS integration to use the regions specified in the AWS config file when no regions are provided in `ossec.conf`. ([#14993](https://github.com/wazuh/wazuh/pull/14993))
- Corrected the error code `#2` for the SIGINT signal within the AWS integration. ([#14850](https://github.com/wazuh/wazuh/pull/14850))
- Fixed the `discard_regex` functionality for the AWS GuardDuty integration. ([#14740](https://github.com/wazuh/wazuh/pull/14740))
- Fixed error messages in the AWS integration when there is a `ClientError`. ([#14500](https://github.com/wazuh/wazuh/pull/14500))
- Fixed error that could lead to duplicate logs when using the same dates in the AWS integration. ([#14493](https://github.com/wazuh/wazuh/pull/14493))
- Fixed `check_bucket` method in AWS integration to be able to find logs without a folder in root. ([#16116](https://github.com/wazuh/wazuh/pull/16116))
- Added field validation for `last_date.json` in Azure Storage integration. ([#16360](https://github.com/wazuh/wazuh/pull/16360))
- Improved handling of invalid regions given to the VPCFlow AWS integration, enhancing exception clarity. ([#15763](https://github.com/wazuh/wazuh/pull/15763))
- Fixed error in the GCloud Subscriber unit tests. ([#16070](https://github.com/wazuh/wazuh/pull/16070))
- Fixed the marker that AWS custom integrations uses. ([#16410](https://github.com/wazuh/wazuh/pull/16410))
- Fixed error messages when there are no logs to process in the WAF and Server Access AWS integrations. ([#16365](https://github.com/wazuh/wazuh/pull/16365))
- Added region validation before instantiating AWS service class in the AWS integration. ([#16463](https://github.com/wazuh/wazuh/pull/16463))
- Fixed InstallDate format in windows installed programs. ([#14161](https://github.com/wazuh/wazuh/pull/14161))
- Fixed syscollector default interval time when the configuration is empty. ([#15428](https://github.com/wazuh/wazuh/issues/15428))
- Fixed agent starts with an invalid fim configuration. ([#16268](https://github.com/wazuh/wazuh/pull/16268))
- Fixed rootcheck scan trying to read deleted files. ([#15719](https://github.com/wazuh/wazuh/pull/15719))
- Fixed compilation and build in Gentoo. ([#15739](https://github.com/wazuh/wazuh/pull/15739))
- Fixed a crash when FIM scan windows longs paths. ([#19375](https://github.com/wazuh/wazuh/pull/19375))
- Fixed FIM who-data support for aarch64 platforms. ([#19378](https://github.com/wazuh/wazuh/pull/19378))

#### Removed

- Unused option `local_ip` for agent configuration has been deleted. ([#13878](https://github.com/wazuh/wazuh/pull/13878))
- Removed unused migration functionality from the AWS integration. ([#14684](https://github.com/wazuh/wazuh/pull/14684))
- Deleted definitions of repeated classes in the AWS integration. ([#17655](https://github.com/wazuh/wazuh/pull/17655))
- Removed duplicate methods in `AWSBucket` and reuse inherited ones from `WazuhIntegration`. ([#15031](https://github.com/wazuh/wazuh/pull/15031))

### RESTful API

#### Added

- Added `POST /events` API endpoint to ingest logs through the API. ([#17670](https://github.com/wazuh/wazuh/pull/17670))
- Added `query`, `select` and `distinct` parameters to multiple endpoints. ([#17865](https://github.com/wazuh/wazuh/pull/17865))
- Added a new upgrade and migration mechanism for the RBAC database. ([#13919](https://github.com/wazuh/wazuh/pull/13919))
- Added new API configuration option to rotate log files based on a given size. ([#13654](https://github.com/wazuh/wazuh/pull/13654))
- Added `relative_dirname` parameter to GET, PUT and DELETE methods of the `/decoder/files/{filename}` and `/rule/files/{filename}` endpoints. ([#15994](https://github.com/wazuh/wazuh/issues/15994))
- Added new config option to disable uploading configurations containing the new `allow_higher_version` setting. ([#18212](https://github.com/wazuh/wazuh/pull/18212))
- Added API integration tests documentation. ([#13615](https://github.com/wazuh/wazuh/pull/13615))

#### Changed

- Changed the API's response status code for Wazuh cluster errors from 400 to 500. ([#13646](https://github.com/wazuh/wazuh/pull/13646))
- Changed Operational API error messages to include additional information. ([#19001](https://github.com/wazuh/wazuh/pull/19001))

#### Fixed

- Fixed an unexpected behavior when using the `q` and `select` parameters in some endpoints. ([#13421](https://github.com/wazuh/wazuh/pull/13421))
- Resolved an issue in the GET /manager/configuration API endpoint when retrieving the vulnerability detector configuration section. ([#15203](https://github.com/wazuh/wazuh/pull/15203))
- Fixed `GET /agents/upgrade_result` endpoint internal error with code 1814 in large environments. ([#15152](https://github.com/wazuh/wazuh/pull/15152))
- Enhanced the alphanumeric_symbols regex to better accommodate specific SCA remediation fields. ([#16756](https://github.com/wazuh/wazuh/pull/16756))
- Fixed bug that would not allow retrieving the Wazuh logs if only the JSON format was configured. ([#15967](https://github.com/wazuh/wazuh/pull/15967))
- Fixed error in `GET /rules` when variables are used inside `id` or `level` ruleset fields. ([#16310](https://github.com/wazuh/wazuh/pull/16310))
- Fixed `PUT /syscheck` and `PUT /rootcheck` endpoints to exclude exception codes properly. ([#16248](https://github.com/wazuh/wazuh/pull/16248))
- Adjusted test_agent_PUT_endpoints.tavern.yaml to resolve a race condition error. ([#16347](https://github.com/wazuh/wazuh/issues/16347))
- Fixed some errors in API integration tests for RBAC white agents. ([#16844](https://github.com/wazuh/wazuh/pull/16844))

#### Removed

- Removed legacy code related to agent databases in `/var/agents/db`. ([#15934](https://github.com/wazuh/wazuh/pull/15934))

### Ruleset

#### Changed

- The SSHD decoder has been improved to catch disconnection events. ([#14138](https://github.com/wazuh/wazuh/pull/14138))


## [v4.5.4]

### Manager

#### Changed

- Set a timeout on requests between components through the cluster. ([#19729](https://github.com/wazuh/wazuh/pull/19729))

#### Fixed

- Fixed a bug that might leave some worker's services hanging if the connection to the master was broken. ([#19702](https://github.com/wazuh/wazuh/pull/19702))
- Fixed vulnerability scan on Windows agent when the OS version has no release data. ([#19706](https://github.com/wazuh/wazuh/pull/19706))


## [v4.5.3] - 2023-10-10

### Manager

#### Changed

- Vulnerability Detector now fetches the SUSE feeds in Gzip compressed format. ([#18783](https://github.com/wazuh/wazuh/pull/18783))

#### Fixed

- Fixed a bug that might cause wazuh-analysisd to crash if it receives a status API query during startup. ([#18737](https://github.com/wazuh/wazuh/pull/18737))
- Fixed a bug that might cause wazuh-maild to crash when handling large alerts. ([#18976](https://github.com/wazuh/wazuh/pull/18976))
- Fixed an issue in Vulnerability Detector fetching the SLES 15 feed. ([#19217](https://github.com/wazuh/wazuh/pull/19217))

### Agent

#### Changed

- Updated the agent to report the name of macOS 14 (Sonoma). ([#19041](https://github.com/wazuh/wazuh/pull/19041))

#### Fixed

- Fixed a bug in the memory handle at the agent's data provider helper. ([#18773](https://github.com/wazuh/wazuh/pull/18773))
- Fixed a data mismatch in the OS name between the global and agents' databases. ([#18903](https://github.com/wazuh/wazuh/pull/18903))
- Fixed an array limit check in wazuh-logcollector. ([#19069](https://github.com/wazuh/wazuh/pull/19069))
- Fixed wrong Windows agent binaries metadata. ([#19286](https://github.com/wazuh/wazuh/pull/19286))
- Fixed error during the windows agent upgrade. ([#19397](https://github.com/wazuh/wazuh/pull/19397))

### RESTful API

#### Added

- Added support for the `$` symbol in query values. ([#18509](https://github.com/wazuh/wazuh/pull/18509))
- Added support for the `@` symbol in query values. ([#18346](https://github.com/wazuh/wazuh/pull/18346))
- Added support for nested queries in the `q` API parameter. ([#18493](https://github.com/wazuh/wazuh/pull/18493))

#### Changed

- Updated `force` flag message in the `agent_upgrade` CLI. ([#18432](https://github.com/wazuh/wazuh/pull/18432))

#### Fixed

- Removed undesired characters when listing rule group names in `GET /rules/groups`. ([#18362](https://github.com/wazuh/wazuh/pull/18362))
- Fixed an error when using the query `condition=all` in `GET /sca/{agent_id}/checks/{policy_id}`. ([#18434](https://github.com/wazuh/wazuh/pull/18434))
- Fixed an error in the API log mechanism where sometimes the requests would not be printed in the log file. ([#18733](https://github.com/wazuh/wazuh/pull/18733))


## [v4.5.2] - 2023-09-06

### Manager

#### Changed

- wazuh-remoted now allows connection overtaking if the older agent did not respond for a while. ([#18085](https://github.com/wazuh/wazuh/pull/18085))
- The manager stops restricting the possible package formats in the inventory, to increase compatibility. ([#18437](https://github.com/wazuh/wazuh/pull/18437))
- wazuh-remoted now prints the connection family when an unknown client gets connected. ([#18468](https://github.com/wazuh/wazuh/pull/18468))
- The manager stops blocking updates by WPK to macOS agents on ARM64, allowing custom updates. ([#18545](https://github.com/wazuh/wazuh/pull/18545))
- Vulnerability Detector now fetches the Debian feeds in BZ2 compressed format. ([#18770](https://github.com/wazuh/wazuh/pull/18770))

### Fixed

- Fixed a bug in wazuh-csyslogd that causes it to consume 100% of CPU while expecting new alerts. ([#18472](https://github.com/wazuh/wazuh/pull/18472))


## [v4.5.1] - 2023-08-24

### Manager

#### Changed

- Vulnerability Detector now fetches the RHEL 5 feed URL from feed.wazuh.com by default. ([#18142](https://github.com/wazuh/wazuh/pull/18142))
- The Vulnerability Detector CPE helper has been updated. ([#16846](https://github.com/wazuh/wazuh/pull/16846))

#### Fixed

- Fixed a race condition in some RBAC unit tests by clearing the SQLAlchemy mappers. ([#17866](https://github.com/wazuh/wazuh/pull/17866))
- Fixed a bug in wazuh-analysisd that could exceed the maximum number of fields when loading a rule. ([#17490](https://github.com/wazuh/wazuh/pull/17490))
- Fixed a race condition in wazuh-analysisd FTS list. ([#17126](https://github.com/wazuh/wazuh/pull/17126))
- Fixed a crash in Analysisd when parsing an invalid decoder. ([#17143](https://github.com/wazuh/wazuh/pull/17143))
- Fixed a segmentation fault in wazuh-modulesd due to duplicate Vulnerability Detector configuration. ([#17701](https://github.com/wazuh/wazuh/pull/17701))
- Fixed Vulnerability Detector configuration for unsupported SUSE systems. ([#16978](https://github.com/wazuh/wazuh/pull/16978))

### Agent

#### Added

- Added the `discard_regex` functionality to Inspector and CloudWatchLogs AWS integrations. ([#17748](https://github.com/wazuh/wazuh/pull/17748))
- Added new validations for the AWS integration arguments. ([#17673](https://github.com/wazuh/wazuh/pull/17673))
- Added native agent support for Apple silicon. ([#2224](https://github.com/wazuh/wazuh-packages/pull/2224))

#### Changed

- The agent for Windows now loads its shared libraries after running the verification. ([#16607](https://github.com/wazuh/wazuh/pull/16607))

#### Fixed

- Fixed `InvalidRange` error in Azure Storage integration when trying to get data from an empty blob. ([#17524](https://github.com/wazuh/wazuh/pull/17524))
- Fixed a memory corruption hazard in the FIM Windows Registry scan. ([#17586](https://github.com/wazuh/wazuh/pull/17586))
- Fixed an error in Syscollector reading the CPU frequency on Apple M1. ([#17179](https://github.com/wazuh/wazuh/pull/17179))
- Fixed agent WPK upgrade for Windows that might leave the previous version in the Registry. ([#16659](https://github.com/wazuh/wazuh/pull/16659))
- Fixed agent WPK upgrade for Windows to get the correct path of the Windows folder. ([#17176](https://github.com/wazuh/wazuh/pull/17176))

### RESTful API

#### Fixed

- Fixed `PUT /agents/upgrade_custom` endpoint to validate that the file extension is `.wpk`. ([#17632](https://github.com/wazuh/wazuh/pull/17632))
- Fixed errors in API endpoints to get `labels` and `reports` active configuration from managers. ([#17660](https://github.com/wazuh/wazuh/pull/17660))

### Ruleset

#### Changed

- The SCA SCA policy for Ubuntu Linux 20.04 (CIS v2.0.0) has been remade. ([#17794](https://github.com/wazuh/wazuh/pull/17794))

#### Fixed

- Fixed CredSSP encryption enforcement at Windows Benchmarks for SCA. ([#17941](https://github.com/wazuh/wazuh/pull/17941))
- Fixed an inverse logic in MS Windows Server 2022 Benchmark for SCA. ([#17940](https://github.com/wazuh/wazuh/pull/17940))
- Fixed a false positive in Windows Eventchannel rule due to substring false positive. ([#17779](https://github.com/wazuh/wazuh/pull/17779))
- Fixed missing whitespaces in SCA policies for Windows. ([#17813](https://github.com/wazuh/wazuh/pull/17813))
- Fixed the description of a Fortigate rule. ([#17798](https://github.com/wazuh/wazuh/pull/17798))

#### Removed

- Removed check 1.1.5 from Windows 10 SCA policy. ([#17812](https://github.com/wazuh/wazuh/pull/17812))

### Other

#### Changed

- The CURL library has been updated to v7.88.1. ([#16990](https://github.com/wazuh/wazuh/pull/16990))


## [v4.5.0] - 2023-08-10

### Manager

#### Changed

- Vulnerability Detector now fetches the NVD feed from https://feed.wazuh.com, based on the NVD API 2.0. ([#17954](https://github.com/wazuh/wazuh/pull/17954))
  - The option `<update_from_year>` has been deprecated.

#### Fixed

- Fixed an error in the installation commands of the API and Framework modules when performing upgrades from sources. ([#17656](https://github.com/wazuh/wazuh/pull/17656))
- Fixed embedded Python interpreter to remove old Wazuh packages from it. ([#18123](https://github.com/wazuh/wazuh/issues/18123))

### RESTful API

#### Changed

- Changed API integration tests to include Nginx LB logs when tests failed. ([#17703](https://github.com/wazuh/wazuh/pull/17703))

#### Fixed

- Fixed error in the Nginx LB entrypoint of the API integration tests. ([#17703](https://github.com/wazuh/wazuh/pull/17703))


## [v4.4.5] - 2023-07-10

### Installer

#### Fixed

- Fixed an error in the DEB package that prevented the agent and manager from being installed on Debian 12. ([#2256](https://github.com/wazuh/wazuh-packages/pull/2256))
- Fixed a service requirement in the RPM package that prevented the agent and manager from being installed on Oracle Linux 9. ([#2257](https://github.com/wazuh/wazuh-packages/pull/2257))


## [v4.4.4] - 2023-06-14

### Manager

#### Fixed

- The vulnerability scanner stops producing false positives for some Windows 11 vulnerabilities due to a change in the feed's CPE. ([#17178](https://github.com/wazuh/wazuh/pull/17178))
- Prevented the VirusTotal integration from querying the API when the source alert is missing the MD5. ([#16908](https://github.com/wazuh/wazuh/pull/16908))

### Agent

#### Changed

- The Windows agent package signing certificate has been updated. ([#17506](https://github.com/wazuh/wazuh/pull/17506))

### Ruleset

#### Changed

- Updated all current rule descriptions from "Ossec" to "Wazuh". ([#17211](https://github.com/wazuh/wazuh/pull/17211))


## [v4.4.3] - 2023-05-26

### Agent

#### Changed

- Added support for Apple Silicon processors to the macOS agent. ([#16521](https://github.com/wazuh/wazuh/pull/16521))
- Prevented the installer from checking the old users "ossecm" and "ossecr" on upgrade. ([#2211](https://github.com/wazuh/wazuh-packages/pull/2211))
- The deployment variables capture has been changed on macOS. ([#17195](https://github.com/wazuh/wazuh/pull/17195))

#### Fixed

- The temporary file "ossec.confre" is now removed after upgrade on macOS. ([#2217](https://github.com/wazuh/wazuh-packages/pull/2217))
- Prevented the installer from corrupting the agent configuration on macOS when deployment variables were defined on upgrade. ([#2208](https://github.com/wazuh/wazuh-packages/pull/2208))
- The installation on macOS has been fixed by removing calls to launchctl. ([#2218](https://github.com/wazuh/wazuh-packages/pull/2218))

### Ruleset

#### Changed

- The SCA policy names have been unified. ([#17202](https://github.com/wazuh/wazuh/pull/17202))


## [v4.4.2] - 2023-05-18

### Manager

#### Changed

- Remove an unused variable in wazuh-authd to fix a _String not null terminated_ Coverity finding. ([#15957](https://github.com/wazuh/wazuh/pull/15957))

#### Fixed

- Fixed a bug causing agent groups tasks status in the cluster not to be stored. ([#16394](https://github.com/wazuh/wazuh/pull/16394))
- Fixed memory leaks in Vulnerability Detector after disk failures. ([#16478](https://github.com/wazuh/wazuh/pull/16478))
- Fixed a pre-decoder problem with the + symbol in the macOS ULS timestamp. ([#16530](https://github.com/wazuh/wazuh/pull/16530))

### Agent

#### Added

- Added a new module to integrate with Amazon Security Lake as a subscriber. ([#16515](https://github.com/wazuh/wazuh/pull/16515))
- Added support for `localfile` blocks deployment. ([#16847](https://github.com/wazuh/wazuh/pull/16847))

#### Changed

- Changed _netstat_ command on macOS agents. ([#16743](https://github.com/wazuh/wazuh/pull/16743))

#### Fixed

- Fixed an issue with MAC address reporting on Windows systems. ([#16517](https://github.com/wazuh/wazuh/pull/16517))
- Fixed Windows unit tests hanging during execution. ([#16857](https://github.com/wazuh/wazuh/pull/16857))

### RESTful API

#### Fixed

- Fixed agent insertion when no key is specified using `POST /agents/insert` endpoint. ([#16381](https://github.com/wazuh/wazuh/pull/16381))

### Ruleset

#### Added

- Added macOS 13.0 Ventura SCA policy. ([#15566](https://github.com/wazuh/wazuh/pull/15566))
- Added new ruleset for macOS 13 Ventura and older versions. ([#15567](https://github.com/wazuh/wazuh/pull/15567))
- Added a new base ruleset for log sources collected from Amazon Security Lake. ([#16549](https://github.com/wazuh/wazuh/pull/16549))

### Other

#### Added

- Added `pyarrow` and `numpy` Python dependencies. ([#16692](https://github.com/wazuh/wazuh/pull/16692))
- Added `importlib-metadata` and `zipp` Python dependencies. ([#16692](https://github.com/wazuh/wazuh/pull/16692))

#### Changed

- Updated `Flask` Python dependency to 2.2.5. ([#17053](https://github.com/wazuh/wazuh/pull/17053))


## [v4.4.1] - 2023-04-12

### Manager

#### Changed

- Improve WazuhDB performance by avoiding synchronization of existing agent keys and removing deprecated agent databases from var/db/agents. ([#15883](https://github.com/wazuh/wazuh/pull/15883))

#### Fixed

- Reverted the addition of some mapping fields in Wazuh template causing a bug with expanded search. ([#16546](https://github.com/wazuh/wazuh/pull/16546))

### RESTful API

#### Changed

- Changed API limits protection to allow uploading new configuration files if `limit` is not modified. ([#16541](https://github.com/wazuh/wazuh/pull/16541))

### Ruleset

#### Added

- Added Debian Linux 11 SCA policy. ([#16017](https://github.com/wazuh/wazuh/pull/16017))

#### Changed

- SCA policy for Red Hat Enterprise Linux 9 rework. ([#16016](https://github.com/wazuh/wazuh/pull/16016))

### Other

#### Changed

- Update embedded Python interpreter to 3.9.16. ([#16472](https://github.com/wazuh/wazuh/issues/16472))
- Update setuptools to 65.5.1. ([#16492](https://github.com/wazuh/wazuh/pull/16492))

## [v4.4.0] - 2023-03-28

### Manager

#### Added

- Added new unit tests for cluster Python module and increased coverage to 99%. ([#9995](https://github.com/wazuh/wazuh/pull/9995))
- Added file size limitation on cluster integrity sync. ([#11190](https://github.com/wazuh/wazuh/pull/11190))
- Added unittests for CLIs script files. ([#13424](https://github.com/wazuh/wazuh/pull/13424))
- Added support for SUSE in Vulnerability Detector. ([#9962](https://github.com/wazuh/wazuh/pull/9962))
- Added support for Ubuntu Jammy in Vulnerability Detector. ([#13263](https://github.com/wazuh/wazuh/pull/13263))
- Added a software limit to limit the number of EPS that a manager can process. ([#13608](https://github.com/wazuh/wazuh/pull/13608))
- Added a new wazuh-clusterd task for agent-groups info synchronization. ([#11753](https://github.com/wazuh/wazuh/pull/11753))
- Added unit tests for functions in charge of getting ruleset sync status. ([#14950](https://github.com/wazuh/wazuh/pull/14950))
- Added auto-vacuum mechanism in wazuh-db. ([#14950](https://github.com/wazuh/wazuh/pull/14950))
- Delta events in Syscollector when data gets changed may now produce alerts. ([#10843](https://github.com/wazuh/wazuh/pull/10843))

#### Changed

- wazuh-logtest now shows warnings about ruleset issues. ([#10822](https://github.com/wazuh/wazuh/pull/10822))
- Modulesd memory is now managed by jemalloc, this helps reduce memory fragmentation. ([#12206](https://github.com/wazuh/wazuh/pull/12206))
- Updated the Vulnerability Detector configuration reporting to include MSU and skip JSON Red Hat feed. ([#12117](https://github.com/wazuh/wazuh/pull/12117))
- Improved the shared configuration file handling performance. ([#12352](https://github.com/wazuh/wazuh/pull/12352))
- The agent group data is now natively handled by Wazuh DB. ([#11753](https://github.com/wazuh/wazuh/pull/11753))
- Improved security at cluster zip filenames creation. ([#10710](https://github.com/wazuh/wazuh/pull/10710))
- Refactor of the core/common.py module. ([#12390](https://github.com/wazuh/wazuh/pull/12390))
- Refactor format_data_into_dictionary method of WazuhDBQuerySyscheck class. ([#12497](https://github.com/wazuh/wazuh/pull/12390))
- Limit the maximum zip size that can be created while synchronizing cluster Integrity. ([#11124](https://github.com/wazuh/wazuh/pull/11124))
- Refactored the functions in charge of synchronizing files in the cluster. ([#13065](https://github.com/wazuh/wazuh/pull/))
- Changed MD5 hash function to BLAKE2 for cluster file comparison. ([#13079](https://github.com/wazuh/wazuh/pull/13079))
- Renamed wazuh-logtest and wazuh-clusterd scripts to follow the same scheme as the other scripts (spaces symbolized with _ instead of -). ([#12926](https://github.com/wazuh/wazuh/pull/12926))
- The agent key polling module has been ported to wazuh-authd. ([#10865](https://github.com/wazuh/wazuh/pull/10865))
- Added the update field in the CPE Helper for Vulnerability Detector. ([#13741](https://github.com/wazuh/wazuh/pull/13741))
- Prevented agents with the same ID from connecting to the manager simultaneously. ([#11702](https://github.com/wazuh/wazuh/pull/11702))
- wazuh-analysisd, wazuh-remoted and wazuh-db metrics have been extended. ([#13713](https://github.com/wazuh/wazuh/pull/13713))
- Minimized and optimized wazuh-clusterd number of messages from workers to master related to agent-info tasks. ([#11753](https://github.com/wazuh/wazuh/pull/11753))
- Improved performance of the `agent_groups` CLI when listing agents belonging to a group. ([#14244](https://github.com/wazuh/wazuh/pull/14244)
- Changed wazuh-clusterd binary behaviour to kill any existing cluster processes when executed. ([#14475](https://github.com/wazuh/wazuh/pull/14475))
- Changed wazuh-clusterd tasks to wait asynchronously for responses coming from wazuh-db. ([#14791](https://github.com/wazuh/wazuh/pull/14843))
- Use zlib for zip compression in cluster synchronization. ([#11190](https://github.com/wazuh/wazuh/pull/11190))
- Added mechanism to dynamically adjust zip size limit in Integrity sync. ([#12241](https://github.com/wazuh/wazuh/pull/12241))
- Deprecate status field in SCA. ([#15853](https://github.com/wazuh/wazuh/pull/15853))
- Agent group guessing (based on configuration hash) now writes the new group directly on the master node. ([#16066](https://github.com/wazuh/wazuh/pull/16066))
- Added delete on cascade of belongs table entries when a group is deleted. ([#16098](https://github.com/wazuh/wazuh/issues/16098))
- Changed `agent_groups` CLI output so affected agents are not printed when deleting a group. ([#16499](https://github.com/wazuh/wazuh/pull/16499))

#### Fixed

- Fixed wazuh-dbd halt procedure. ([#10873](https://github.com/wazuh/wazuh/pull/10873))
- Fixed compilation warnings in the manager. ([#12098](https://github.com/wazuh/wazuh/pull/12098))
- Fixed a bug in the manager that did not send shared folders correctly to agents belonging to multiple groups. ([#12516](https://github.com/wazuh/wazuh/pull/12516))
- Fixed the Active Response decoders to support back the top entries for source IP in reports. ([#12834](https://github.com/wazuh/wazuh/pull/12834))
- Fixed the feed update interval option of Vulnerability Detector for the JSON Red Hat feed. ([#13338](https://github.com/wazuh/wazuh/pull/13338))
- Fixed several code flaws in the Python framework. ([#12127](https://github.com/wazuh/wazuh/pull/12127))
  - Fixed code flaw regarding the use of XML package. ([#10635](https://github.com/wazuh/wazuh/pull/10635))
  - Fixed code flaw regarding permissions at group directories. ([#10636](https://github.com/wazuh/wazuh/pull/10636))
  - Fixed code flaw regarding temporary directory names. ([#10544](https://github.com/wazuh/wazuh/pull/10544))
  - Fixed code flaw regarding try, except and pass block in wazuh-clusterd. ([#11951](https://github.com/wazuh/wazuh/pull/11951))
- Fixed framework datetime transformations to UTC. ([#10782](https://github.com/wazuh/wazuh/pull/10782))
- Fixed a cluster error when Master-Worker tasks where not properly stopped after an exception occurred in one or both parts. ([#11866](https://github.com/wazuh/wazuh/pull/11866))
- Fixed cluster logger issue printing 'NoneType: None' in error logs. ([#12831](https://github.com/wazuh/wazuh/pull/12831))
- Fixed unhandled cluster error when reading a malformed configuration. ([#13419](https://github.com/wazuh/wazuh/pull/13419))
- Fixed framework unit test failures when they are run by the root user. ([#13368](https://github.com/wazuh/wazuh/pull/13368))
- Fixed a memory leak in analysisd when parsing a disabled Active Response. ([#13405](https://github.com/wazuh/wazuh/pull/13405))
- Prevented wazuh-db from deleting queue/diff when cleaning databases. ([#13892](https://github.com/wazuh/wazuh/pull/13892))
- Fixed multiple data race conditions in Remoted reported by ThreadSanitizer. ([#14981](https://github.com/wazuh/wazuh/pull/14981))
- Fixed aarch64 OS collection in Remoted to allow WPK upgrades. ([#15151](https://github.com/wazuh/wazuh/pull/15151))
- Fixed a race condition in Remoted that was blocking agent connections. ([#15165](https://github.com/wazuh/wazuh/pull/15165))
- Fixed Virustotal integration to support non UTF-8 characters. ([#13531](https://github.com/wazuh/wazuh/pull/13531))
- Fixed a bug masking as Timeout any error that might occur while waiting to receive files in the cluster. ([#14922](https://github.com/wazuh/wazuh/pull/14922))
- Fixed a read buffer overflow in wazuh-authd when parsing requests. ([#15876](https://github.com/wazuh/wazuh/pull/15876))
- Applied workaround for bpo-46309 used in cluster to wazuh-db communication.([#16012](https://github.com/wazuh/wazuh/pull/16012))
- Let the database module synchronize the agent groups data before assignments. ([#16233](https://github.com/wazuh/wazuh/pull/16233))
- Fixed memory leaks in wazuh-analysisd when parsing and matching rules. ([#16321](https://github.com/wazuh/wazuh/pull/16321))

#### Removed

- Removed the unused internal option `wazuh_db.sock_queue_size`. ([#12409](https://github.com/wazuh/wazuh/pull/12409))
- Removed all the unused exceptions from the exceptions.py file.  ([#10940](https://github.com/wazuh/wazuh/pull/10940))
- Removed unused execute method from core/utils.py. ([#10740](https://github.com/wazuh/wazuh/pull/10740))
- Removed unused set_user_name function in framework. ([#13119](https://github.com/wazuh/wazuh/pull/13119))
- Unused internal calls to wazuh-db have been deprecated. ([#12370](https://github.com/wazuh/wazuh/pull/12370))
- Debian Stretch support in Vulnerability Detector has been deprecated. ([#14542](https://github.com/wazuh/wazuh/pull/14542))

### Agent

#### Added

- Added support of CPU frequency data provided by Syscollector on Raspberry Pi. ([#11756](https://github.com/wazuh/wazuh/pull/11756))
- Added support for IPv6 address collection in the agent. ([#11450](https://github.com/wazuh/wazuh/pull/11450))
- Added the process startup time data provided by Syscollector on macOS. ([#11833](https://github.com/wazuh/wazuh/pull/11833))
- Added support of package retrieval in Syscollector for OpenSUSE Tumbleweed and Fedora 34. ([#11571](https://github.com/wazuh/wazuh/pull/11571))
- Added the process startup time data provided by Syscollector on macOS. Thanks to @LubinLew. ([#11640](https://github.com/wazuh/wazuh/pull/11640))
- Added support for package data provided by Syscollector on Solaris. ([#11796](https://github.com/wazuh/wazuh/pull/11796))
- Added support for delta events in Syscollector when data gets changed. ([#10843](https://github.com/wazuh/wazuh/pull/10843))
- Added support for pre-installed Windows packages in Syscollector. ([#12035](https://github.com/wazuh/wazuh/pull/12035))
- Added support for IPv6 on agent-manager connection and enrollment. ([#11268](https://github.com/wazuh/wazuh/pull/11268))
- Added support for CIS-CAT Pro v3 and v4 to the CIS-CAT integration module. Thanks to @hustliyilin. ([#12582](https://github.com/wazuh/wazuh/pull/12582))
- Added support for the use of the Azure integration module in Linux agents. ([#10870](https://github.com/wazuh/wazuh/pull/10870))
- Added new error messages when using invalid credentials with the Azure integration. ([#11852](https://github.com/wazuh/wazuh/pull/11852))
- Added reparse option to CloudWatchLogs and Google Cloud Storage integrations.  ([#12515](https://github.com/wazuh/wazuh/pull/12515))
- Wazuh Agent can now be built and run on Alpine Linux. ([#14726](https://github.com/wazuh/wazuh/pull/14726))
- Added native Shuffle integration. ([#15054](https://github.com/wazuh/wazuh/pull/15054))

#### Changed

- Improved the free RAM data provided by Syscollector. ([#11587](https://github.com/wazuh/wazuh/pull/11587))
- The Windows installer (MSI) now provides signed DLL files. ([#12752](https://github.com/wazuh/wazuh/pull/12752))
- Changed the group ownership of the Modulesd process to root. ([#12748](https://github.com/wazuh/wazuh/pull/12748))
- Some parts of Agentd and Execd have got refactored. ([#12750](https://github.com/wazuh/wazuh/pull/12750))
- Handled new exception in the external integration modules. ([#10478](https://github.com/wazuh/wazuh/pull/10478))
- Optimized the number of calls to DB maintenance tasks performed by the AWS integration. ([#11828](https://github.com/wazuh/wazuh/pull/11828))
- Improved the reparse setting performance by removing unnecessary queries from external integrations. ([#12404](https://github.com/wazuh/wazuh/pull/12404))
- Updated and expanded Azure module logging functionality to use the ossec.log file. ([#12478](https://github.com/wazuh/wazuh/pull/12478))
- Improved the error management of the Google Cloud integration. ([#12647](https://github.com/wazuh/wazuh/pull/12647))
- Deprecated `logging` tag in GCloud integration. It now uses `wazuh_modules` debug value to set the verbosity level. ([#12769](https://github.com/wazuh/wazuh/pull/12769))
- The last_dates.json file of the Azure module has been deprecated in favour of a new ORM and database. ([12849](https://github.com/wazuh/wazuh/pull/12849/))
- Improved the error handling in AWS integration's `decompress_file` method. ([#12929](https://github.com/wazuh/wazuh/pull/12929))
- Use zlib for zip compression in cluster synchronization. ([#11190](https://github.com/wazuh/wazuh/pull/11190))
- The exception handling on Wazuh Agent for Windows has been changed to DWARF2. ([#11354](https://github.com/wazuh/wazuh/pull/11354))
- The root CA certificate for WPK upgrade has been updated. ([#14696](https://github.com/wazuh/wazuh/pull/14696))
- Agents on macOS now report the OS name as "macOS" instead of "Mac OS X". ([#14822](https://github.com/wazuh/wazuh/pull/14822))
- The Systemd service stopping policy has been updated. ([#14816](https://github.com/wazuh/wazuh/pull/14816))
- Changed how the AWS module handles `ThrottlingException` adding default values for connection retries in case no config file is set.([#14793](https://github.com/wazuh/wazuh/pull/14793))
- The agent for Windows now verifies its libraries to prevent side loading. ([#15404](https://github.com/wazuh/wazuh/pull/15404))

#### Fixed

- Fixed collection of maximum user data length. Thanks to @LubinLew. ([#7687](https://github.com/wazuh/wazuh/pull/7687))
- Fixed missing fields in Syscollector on Windows 10. ([#10772](https://github.com/wazuh/wazuh/pull/10772))
- Fixed the process startup time data provided by Syscollector on Linux. Thanks to @LubinLew. ([#11227](https://github.com/wazuh/wazuh/pull/11227))
- Fixed network data reporting by Syscollector related to tunnel or VPN interfaces. ([#11837](https://github.com/wazuh/wazuh/pull/11837))
- Skipped V9FS file system at Rootcheck to prevent false positives on WSL. ([#12066](https://github.com/wazuh/wazuh/pull/12066))
- Fixed double file handle closing in Logcollector on Windows. ([#9067](https://github.com/wazuh/wazuh/pull/9067))
- Fixed a bug in Syscollector that may prevent the agent from stopping when the manager connection is lost. ([#11949](https://github.com/wazuh/wazuh/pull/11949))
- Fixed internal exception handling issues on Solaris 10. ([#12148](https://github.com/wazuh/wazuh/pull/12148))
- Fixed duplicate error message IDs in the log. ([#12300](https://github.com/wazuh/wazuh/pull/12300))
- Fixed compilation warnings in the agent. ([#12691](https://github.com/wazuh/wazuh/pull/12691))
- Fixed the `skip_on_error` parameter of the AWS integration module, which was set to `True` by default. ([#1247](https://github.com/wazuh/wazuh/pull/12147))
- Fixed AWS DB maintenance with Load Balancer Buckets. ([#12381](https://github.com/wazuh/wazuh/pull/12381))
- Fixed AWS integration's `test_config_format_created_date` unit test. ([#12650](https://github.com/wazuh/wazuh/pull/12650))
- Fixed created_date field for LB and Umbrella integrations. ([#12630](https://github.com/wazuh/wazuh/pull/12630))
- Fixed AWS integration database maintenance error managament. ([#13185](https://github.com/wazuh/wazuh/pull/13185))
- The default delay at GitHub integration has been increased to 30 seconds. ([#13674](https://github.com/wazuh/wazuh/pull/13674))
- Logcollector has been fixed to allow locations containing colons (:). ([#14706](https://github.com/wazuh/wazuh/pull/14706))
- Fixed system architecture reporting in Syscollector on Apple Silicon devices. ([#13835](https://github.com/wazuh/wazuh/pull/13835))
- The C++ standard library and the GCC runtime library is included with Wazuh. ([#14190](https://github.com/wazuh/wazuh/pull/14190))
- Fixed missing inventory cleaning message in Syscollector. ([#13877](https://github.com/wazuh/wazuh/pull/13877))
- Fixed WPK upgrade issue on Windows agents due to process locking. ([#15322](https://github.com/wazuh/wazuh/pull/15322))
- Fixed FIM injection vulnerabilty when using `prefilter_cmd` option. ([#13044](https://github.com/wazuh/wazuh/pull/13044))
- Fixed the parse of ALB logs splitting `client_port`, `target_port` and `target_port_list` in separated `ip` and `port` for each key. ([14525](https://github.com/wazuh/wazuh/pull/14525))
- Fixed a bug that prevent processing Macie logs with problematic ipGeolocation values. ([15335](https://github.com/wazuh/wazuh/pull/15335))
- Fixed GCP integration module error messages. ([#15584](https://github.com/wazuh/wazuh/pull/15584))
- Fixed an error that prevented the agent on Windows from stopping correctly. ([#15575](https://github.com/wazuh/wazuh/pull/15575))
- Fixed Azure integration credentials link. ([#16140](https://github.com/wazuh/wazuh/pull/16140))

#### Removed

- Deprecated Azure and AWS credentials in the configuration authentication option. ([#14543](https://github.com/wazuh/wazuh/pull/14543))

### RESTful API

#### Added

- Added new API integration tests for a Wazuh environment without a cluster configuration. ([#10620](https://github.com/wazuh/wazuh/pull/10620))
- Added wazuh-modulesd tags to `GET /manager/logs` and `GET /cluster/{node_id}/logs` endpoints. ([#11731](https://github.com/wazuh/wazuh/pull/11731))
- Added Python decorator to soft deprecate API endpoints adding deprecation headers to their responses. ([#12438](https://github.com/wazuh/wazuh/pull/12438))
- Added new exception to inform that /proc directory is not found or permissions to see its status are not granted. ([#12486](https://github.com/wazuh/wazuh/pull/12486))
- Added new field and filter to `GET /agents` response to retrieve agent groups configuration synchronization status. ([#12362](https://github.com/wazuh/wazuh/pull/12483))
- Added agent groups configuration synchronization status to `GET /agents/summary/status` endpoint. ([12498](https://github.com/wazuh/wazuh/pull/12498))
- Added JSON log handling. ([#11171](https://github.com/wazuh/wazuh/pull/11171))
- Added integration tests for IPv6 agent's registration. ([#12029](https://github.com/wazuh/wazuh/pull/12029))
- Enable ordering by Agents count in `/groups` endpoints. ([#12887](https://github.com/wazuh/wazuh/pull/12887))
- Added hash to API logs to identify users logged in with authorization context. ([#12092](https://github.com/wazuh/wazuh/pull/12092))
- Added new `limits` section to the `upload_wazuh_configuration` section in the Wazuh API configuration. ([#14119](https://github.com/wazuh/wazuh/pull/14119))
- Added logic to API logger to renew its streams if needed on every request. ([#14295](https://github.com/wazuh/wazuh/pull/14295))
- Added `GET /manager/daemons/stats` and `GET /cluster/{node_id}/daemons/stats` API endpoints. ([#14401](https://github.com/wazuh/wazuh/pull/14401))
- Added `GET /agents/{agent_id}/daemons/stats` API endpoint. ([#14464](https://github.com/wazuh/wazuh/pull/14464))
- Added the possibility to get the configuration of the `wazuh-db` component in active configuration endpoints. ([#14471](https://github.com/wazuh/wazuh/pull/14471))
- Added distinct and select parameters to GET /sca/{agent_id} and GET /sca/{agent_id}/checks/{policy_id} endpoints. ([#15084](https://github.com/wazuh/wazuh/pull/15084))
- Added new endpoint to run vulnerability detector on-demand scans (`PUT /vulnerability`). ([#15290](https://github.com/wazuh/wazuh/pull/15290))

#### Changed

- Improved `GET /cluster/healthcheck` endpoint and `cluster_control -i more` CLI call in loaded cluster environments. ([#11341](https://github.com/wazuh/wazuh/pull/11341))
- Removed `never_connected` agent status limitation when trying to assign agents to groups. ([#12595](https://github.com/wazuh/wazuh/pull/12595))
- Changed API version and upgrade_version filters to work with different version formats. ([#12551](https://github.com/wazuh/wazuh/pull/12551))
- Renamed `GET /agents/{agent_id}/group/is_sync` endpoint to `GET /agents/group/is_sync` and added new `agents_list` parameter. ([#9413](https://github.com/wazuh/wazuh/pull/9413))
- Added `POST /security/user/authenticate` endpoint and marked `GET /security/user/authenticate` endpoint as deprecated. ([#10397](https://github.com/wazuh/wazuh/pull/10397))
- Adapted framework code to agent-group changes to use the new wazuh-db commands. ([#12526](https://github.com/wazuh/wazuh/pull/12526))
- Updated default timeout for `GET /mitre/software` to avoid timing out in slow environments after the MITRE DB update to v11.2. ([#13791](https://github.com/wazuh/wazuh/pull/13791))
- Changed API settings related to remote commands. The `remote_commands` section will be hold within `upload_wazuh_configuration`. ([#14119](https://github.com/wazuh/wazuh/pull/14119))
- Improved API unauthorized responses to be more accurate. ([#14233](https://github.com/wazuh/wazuh/pull/14233))
- Updated framework functions that communicate with the `request` socket to use `remote` instead. ([#14259](https://github.com/wazuh/wazuh/pull/14259))
- Improved parameter validation for API endpoints that require component and configuration parameters. ([#14766](https://github.com/wazuh/wazuh/pull/14766))
- Improved `GET /sca/{agent_id}/checks/{policy_id}` API endpoint performance. ([#15017](https://github.com/wazuh/wazuh/pull/15017))
- Improved exception handling when trying to connect to Wazuh sockets. ([#15334](https://github.com/wazuh/wazuh/pull/15334))
- Modified _group_names and _group_names_or_all regexes to avoid invalid group names. ([#15671](https://github.com/wazuh/wazuh/pull/15671))
- Changed `GET /sca/{agent_id}/checks/{policy_id}` endpoint filters and response to remove `status` field. ([#15747](https://github.com/wazuh/wazuh/pull/15747))
- Removed RBAC group assignments' related permissions from `DELETE /groups` to improve performance and changed response structure. ([#16231](https://github.com/wazuh/wazuh/pull/16231))

#### Fixed

- Fixed copy functions used for the backup files and upload endpoints to prevent incorrent metadata. ([#12302](https://github.com/wazuh/wazuh/pull/12302))
- Fixed a bug regarding ids not being sorted with cluster disabled in Active Response and Agent endpoints. ([#11010](https://github.com/wazuh/wazuh/pull/11010))
- Fixed a bug where `null` values from wazuh-db where returned in API responses. ([#10736](https://github.com/wazuh/wazuh/pull/10736))
- Connections through `WazuhQueue` will be closed gracefully in all situations. ([#12063](https://github.com/wazuh/wazuh/pull/12063))
- Fixed exception handling when trying to get the active configuration of a valid but not configured component. ([#12450](https://github.com/wazuh/wazuh/pull/12450))
- Fixed api.yaml path suggested as remediation at exception.py ([#12700](https://github.com/wazuh/wazuh/pull/12700))
- Fixed /tmp access error in containers of API integration tests environment. ([#12768](https://github.com/wazuh/wazuh/pull/12768))
- The API will return an exception when the user asks for agent inventory information and there is no database for it (never connected agents). ([#13096](https://github.com/wazuh/wazuh/pull/13096))
- Improved regex used for the `q` parameter on API requests with special characters and brackets. ([#13171](https://github.com/wazuh/wazuh/pull/13171)) ([#13386](https://github.com/wazuh/wazuh/pull/13386))
- Removed board_serial from syscollector integration tests expected responses. ([#12592](https://github.com/wazuh/wazuh/pull/12592))
- Removed cmd field from expected responses of syscollector integration tests. ([#12557](https://github.com/wazuh/wazuh/pull/12557))
- Reduced maximum number of groups per agent to 128 and adjusted group name validation. ([#12611](https://github.com/wazuh/wazuh/pull/12611))
- Reduced amount of memory required to read CDB lists using the API. ([#14204](https://github.com/wazuh/wazuh/pull/14204))
- Fixed a bug where the cluster health check endpoint and CLI would add an extra active agent to the master node. ([#14237](https://github.com/wazuh/wazuh/pull/14237))
- Fixed bug that prevent updating the configuration when using various <ossec_conf> blocks from the API ([#15311](https://github.com/wazuh/wazuh/pull/15311))
- Fixed vulnerability API integration tests' healthcheck. ([#15194](https://github.com/wazuh/wazuh/pull/15194))

#### Removed

- Removed null remediations from failed API responses. ([#12053](https://github.com/wazuh/wazuh/pull/12053))
- Deprecated `GET /agents/{agent_id}/group/is_sync` endpoint. ([#12365](https://github.com/wazuh/wazuh/issues/12365))
- Deprecated `GET /manager/stats/analysisd`, `GET /manager/stats/remoted`, `GET /cluster/{node_id}stats/analysisd`, and `GET /cluster/{node_id}stats/remoted` API endpoints. ([#14230](https://github.com/wazuh/wazuh/pull/14230))

### Ruleset

#### Added

- Added support for new sysmon events. ([#13594](https://github.com/wazuh/wazuh/pull/13594))
- Added new detection rules using Sysmon ID 1 events. ([#13595](https://github.com/wazuh/wazuh/pull/13595))
- Added new detection rules using Sysmon ID 3 events. ([#13596](https://github.com/wazuh/wazuh/pull/13596))
- Added new detection rules using Sysmon ID 7 events. ([#13630](https://github.com/wazuh/wazuh/pull/13630))
- Added new detection rules using Sysmon ID 8 events. ([#13637](https://github.com/wazuh/wazuh/pull/13637))
- Added new detection rules using Sysmon ID 10 events. ([#13639](https://github.com/wazuh/wazuh/pull/13639))
- Added new detection rules using Sysmon ID 11 events. ([#13631](https://github.com/wazuh/wazuh/pull/13631))
- Added new detection rules using Sysmon ID 13 events. ([#13636](https://github.com/wazuh/wazuh/pull/13636))
- Added new detection rules using Sysmon ID 20 events. ([#13673](https://github.com/wazuh/wazuh/pull/13673))
- Added new PowerShell ScriptBlock detection rules. ([#13638](https://github.com/wazuh/wazuh/pull/13638))
- Added HPUX 11i SCA policies using bastille and without bastille. ([#15157](https://github.com/wazuh/wazuh/pull/15157))

#### Changed

- Updated ruleset according to new API log changes when the user is logged in with authorization context. ([#15072](https://github.com/wazuh/wazuh/pull/15072))
- Updated 0580-win-security_rules.xml rules. ([#13579](https://github.com/wazuh/wazuh/pull/13579))
- Updated Wazuh MITRE ATT&CK database to version 11.3. ([#13622](https://github.com/wazuh/wazuh/pull/13622))
- Updated detection rules in 0840-win_event_channel.xml. ([#13633](https://github.com/wazuh/wazuh/pull/13633))
- SCA policy for Ubuntu Linux 20.04 rework. ([#15070](https://github.com/wazuh/wazuh/pull/15070))
- Updated Ubuntu Linux 22.04 SCA Policy with CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0. ([#15051](https://github.com/wazuh/wazuh/pull/15051))

#### Fixed

- Fixed OpenWRT decoder fixed to parse UFW logs. ([#11613](https://github.com/wazuh/wazuh/pull/11613))
- Bug fix in wazuh-api-fields decoder. ([#14807](https://github.com/wazuh/wazuh/pull/14807))
- Fixed deprecated MITRE tags in rules. ([#13567](https://github.com/wazuh/wazuh/pull/13567))
- SCA checks IDs are not unique. ([#15241](https://github.com/wazuh/wazuh/pull/15241))
- Fixed regex in check 5.1.1 of Ubuntu 20.04 SCA. ([#14513](https://github.com/wazuh/wazuh/pull/14513))
- Removed wrong Fedora Linux SCA default policies. ([#15251](https://github.com/wazuh/wazuh/pull/15251))
- SUSE Linux Enterprise 15 SCA Policy duplicated check ids 7521 and 7522. ([#15156](https://github.com/wazuh/wazuh/pull/15156))

### Other

#### Added

- Added unit tests to the component in Analysisd that extracts the IP address from events. ([#12733](https://github.com/wazuh/wazuh/pull/12733))
- Added `python-json-logger` dependency. ([#12518](https://github.com/wazuh/wazuh/pull/12518))

#### Changed

- Prevented the Ruleset test suite from restarting the manager. ([#10773](https://github.com/wazuh/wazuh/pull/10773))
- The pthread's rwlock has been replaced with a FIFO-queueing read-write lock. ([#14839](https://github.com/wazuh/wazuh/pull/14839))
- Updated Python dependency certifi to 2022.12.7. ([#15809](https://github.com/wazuh/wazuh/pull/15809))
- Updated Python dependency future to 0.18.3. ([#15896](https://github.com/wazuh/wazuh/pull/15896))
- Updated Werkzeug to 2.2.3. ([#16317](https://github.com/wazuh/wazuh/pull/16317))
- Updated Flask to 2.0.0. ([#16317](https://github.com/wazuh/wazuh/pull/16317))
- Updated itsdangerous to 2.0.0. ([#16317](https://github.com/wazuh/wazuh/pull/16317))
- Updated Jinja2 to 3.0.0. ([#16317](https://github.com/wazuh/wazuh/pull/16317))
- Updated MarkupSafe to 2.1.2. ([#16317](https://github.com/wazuh/wazuh/pull/16317))

#### Fixed

- Fixed Makefile to detect CPU archivecture on Gentoo Linux. ([#14165](https://github.com/wazuh/wazuh/pull/14165))


## [v4.3.11] - 2023-04-24

### Manager

#### Fixed

- Fixed a dead code bug that might cause wazuh-db to crash. ([#16752](https://github.com/wazuh/wazuh/pull/16752))


## [v4.3.10] - 2022-11-16

### Manager

#### Fixed

- Updated the Arch Linux feed URL in Vulnerability Detector. ([#15219](https://github.com/wazuh/wazuh/pull/15219))
- Fixed a bug in Vulnerability Detector related to internal database access. ([#15197](https://github.com/wazuh/wazuh/pull/15197))
- Fixed a crash hazard in Analysisd when parsing an invalid `<if_sid>` value in the ruleset. ([#15303](https://github.com/wazuh/wazuh/pull/15303))

### Agent

#### Fixed

- The agent upgrade configuration has been restricted to local settings. ([#15259](https://github.com/wazuh/wazuh/pull/15259))
- Fixed unwanted Windows agent configuration modification on upgrade. ([#15262](https://github.com/wazuh/wazuh/pull/15262))


## [v4.3.9] - 2022-10-13

### Agent

#### Fixed

- Fixed remote policy detection in SCA. ([#15007](https://github.com/wazuh/wazuh/pull/15007))
- Fixed agent upgrade module settings parser to set a default CA file. ([#15023](https://github.com/wazuh/wazuh/pull/15023))

#### Removed

- Removed obsolete Windows Audit SCA policy file. ([#14497](https://github.com/wazuh/wazuh/issues/14497))

### Other

#### Changed

- Updated external protobuf python dependency to 3.19.6. ([#15067](https://github.com/wazuh/wazuh/pull/15067))


## [v4.3.8] - 2022-09-19

### Manager

#### Fixed

- Fixed wrong field assignation in Audit decoders (thanks to @pyama86). ([#14752](https://github.com/wazuh/wazuh/pull/14752))
- Prevented wazuh-remoted from cleaning the multigroup folder in worker nodes. ([#14825](https://github.com/wazuh/wazuh/pull/14825))
- Fixed rule skipping in wazuh-analysisd when the option if_sid is invalid. ([#14772](https://github.com/wazuh/wazuh/pull/14772))

### Agent

#### Changed

- Updated root CA certificate in agents to validate WPK upgrades. ([#14842](https://github.com/wazuh/wazuh/pull/14842))

#### Fixed

- Fixed a path traversal flaw in Active Response affecting agents from v3.6.1 to v4.3.7 (reported by @guragainroshan0). ([#14801](https://github.com/wazuh/wazuh/pull/14801))


## [v4.3.7] - 2022-08-24

### Manager

#### Added

- Added cluster command to obtain custom ruleset files and their hash. ([#14540](https://github.com/wazuh/wazuh/pull/14540))

#### Fixed

- Fixed a bug in Analysisd that may make it crash when decoding regexes with more than 14 or-ed subpatterns. ([#13956](https://github.com/wazuh/wazuh/pull/13956))
- Fixed a crash hazard in Vulnerability Detector when parsing OVAL feeds. ([#14366](https://github.com/wazuh/wazuh/pull/14366))
- Fixed busy-looping in wazuh-maild when monitoring alerts.json. ([#14436](https://github.com/wazuh/wazuh/pull/14436))
- Fixed a segmentation fault in wazuh-maild when parsing alerts exceeding the nesting limit. ([#14417](https://github.com/wazuh/wazuh/pull/14417))

### Agent

#### Changed

- Improved Office365 integration module logs. ([#13958](https://github.com/wazuh/wazuh/pull/13958))

#### Fixed

- Fixed a code defect in the GitHub integration module reported by Coverity. ([#14368](https://github.com/wazuh/wazuh/pull/14368))
- Fixed an undefined behavior in the agent unit tests. ([#14518](https://github.com/wazuh/wazuh/pull/14518))

### RESTful API

#### Added

- Added endpoint GET /cluster/ruleset/synchronization to check ruleset synchronization status in a cluster. ([#14551](https://github.com/wazuh/wazuh/pull/14551))

#### Changed

- Improved performance for MITRE API endpoints. ([#14208](https://github.com/wazuh/wazuh/pull/14208))

### Ruleset

#### Added

- Added SCA Policy for CIS Microsoft Windows 11 Enterprise Benchmark v1.0.0. ([#13806](https://github.com/wazuh/wazuh/pull/13806))
- Added SCA Policy for CIS Microsoft Windows 10 Enterprise Release 21H2 Benchmark v1.12.0. ([#13879](https://github.com/wazuh/wazuh/pull/13879))
- Added SCA policy for Red Hat Enterprise Linux 9 (RHEL9). ([#13843](https://github.com/wazuh/wazuh/pull/13843))
- Added SCA policy for CIS Microsoft Windows Server 2022 Benchmark 1.0.0. ([#13899](https://github.com/wazuh/wazuh/pull/13899))

#### Fixed

- Fixed rule regular expression bug on Ubuntu 20.04 Linux SCA policy control ID 19137. ([#14513](https://github.com/wazuh/wazuh/pull/14513))
- Fixed AWS Amazon Linux SCA policy. Fixed bug when wazuh-agent tries to run the policy. ([#14483](https://github.com/wazuh/wazuh/pull/14483))
- Fixed AWS Amazon Linux 2 SCA policy. Limit journalctl to kernel events and only since boot. ([#13950](https://github.com/wazuh/wazuh/pull/13950))
- Added missing SCA files during Wazuh-manager installation. ([#14482](https://github.com/wazuh/wazuh/pull/14482))
- Fixed OS detection in Ubuntu 20.04 LTS SCA policy. ([#14678](https://github.com/wazuh/wazuh/pull/14678))


## [v4.3.6] - 2022-07-20

### Manager

#### Added

- Added support for Ubuntu 22 (Jammy) in Vulnerability Detector. ([#14085](https://github.com/wazuh/wazuh/pull/14085))
- Addded support for Red Hat 9 in Vulnerability Detector. ([#14117](https://github.com/wazuh/wazuh/pull/14117))

#### Changed

- Improved the shared configuration file handling performance in wazuh-remoted. ([#14111](https://github.com/wazuh/wazuh/pull/14111))

#### Fixed

- Fixed potential memory leaks in Vulnerability Detector when parsing OVAL with no criteria. ([#14098](https://github.com/wazuh/wazuh/pull/14098))
- Fixed a bug in Vulnerability Detector that skipped Windows 8.1 and Windows 8 agents. ([#13957](https://github.com/wazuh/wazuh/pull/13957))
- Fixed a bug in wazuh-db that stored duplicate Syscollector package data. ([#14061](https://github.com/wazuh/wazuh/pull/14061))

### Agent

#### Changed

- Updated macOS codename list in Syscollector. ([#13837](https://github.com/wazuh/wazuh/pull/13837))
- Improved GitHub and Office365 integrations log messages. ([#14093](https://github.com/wazuh/wazuh/pull/14093))

#### Fixed

- Fixed agent shutdown when syncing Syscollector data. ([#13941](https://github.com/wazuh/wazuh/pull/13941))
- Fixed a bug in the agent installer that misdetected the wazuh username. ([#14207](https://github.com/wazuh/wazuh/pull/14207))
- Fixed macOS vendor data retrieval in Syscollector. ([#14100](https://github.com/wazuh/wazuh/pull/14100))
- Fixed a bug in the Syscollector data sync when the agent gets disconnected. ([#14106](https://github.com/wazuh/wazuh/pull/14106))
- Fixed a crash in the Windows agent caused by the Syscollector SMBIOS parser for Windows agents. ([#13980](https://github.com/wazuh/wazuh/pull/13980))

### RESTful API

#### Fixed

- Return an exception when the user asks for agent inventory information where there is no database for it, such as never_connected agents. ([#14152](https://github.com/wazuh/wazuh/pull/14152))
- Fixed bug with `q` parameter in the API when using brace characters. ([#14088](https://github.com/wazuh/wazuh/pull/14088))

### Ruleset

#### Added

- Added Ubuntu Linux 22.04 SCA Policy. ([#13893](https://github.com/wazuh/wazuh/pull/13893))
- Added Apple macOS 12.0 Monterey SCA Policy. ([#13905](https://github.com/wazuh/wazuh/pull/13905))

### Other

#### Changed

- Disabled filebeat logging metrics. ([#14121](https://github.com/wazuh/wazuh/pull/14121))


## [v4.3.5] - 2022-06-29

### Manager

#### Changed

- Improved the Vulnerability Detector's log when the agent's OS data is unavailable. ([#13915](https://github.com/wazuh/wazuh/pull/13915))

#### Fixed

- The upgrade module's response message has been fixed not to include null values. ([#13662](https://github.com/wazuh/wazuh/pull/13662))
- Fixed a string truncation warning log in wazuh-authd when enabling password authentication. ([#13863](https://github.com/wazuh/wazuh/pull/13863))
- Fixed a memory leak in wazuh-analysisd when overwriting a rule multiple times. ([#13587](https://github.com/wazuh/wazuh/pull/13587))
- Prevented wazuh-agentd and client-auth from performing enrollment if the agent fails to validate the manager's certificate. ([#13907](https://github.com/wazuh/wazuh/pull/13907))
- Fixed manager's compilation when enabling GeoIP support. ([#13694](https://github.com/wazuh/wazuh/pull/13694))
- Fixed a crash in wazuh-modulesd when getting stopped while downloading a Vulnerability Detector feed. ([#13883](https://github.com/wazuh/wazuh/pull/13883))

### Agent

#### Changed

- Extended package data support in Syscollector for modern RPM agents. ([#13749](https://github.com/wazuh/wazuh/pull/13749))
- Improved verbosity of the GitHub module logs. ([#13898](https://github.com/wazuh/wazuh/pull/13898))

#### Fixed

- Fixed agent auto-restart on shared configuration changes when running on containerized environments. ([#13606](https://github.com/wazuh/wazuh/pull/13606))
- Fixed an issue when attempting to run the DockerListener integration using Python 3.6 and having the Docker service stopped. ([#13880](https://github.com/wazuh/wazuh/pull/13880))

### RESTful API

#### Fixed
- Updated `tag` parameter of `GET /manager/logs` and `GET /cluster/{node_id}/logs` endpoints to accept any string. ([#13867](https://github.com/wazuh/wazuh/pull/13867))

### Ruleset

#### Fixed

- Solved Eventchannel testing and improved reporting capabilities of the runtest tool. ([#13597](https://github.com/wazuh/wazuh/pull/13597))
- Modified Amazon Linux 2 SCA policy to resolve a typo on control 1.1.22 and `EMPTY_LINE` conditions. ([#13781](https://github.com/wazuh/wazuh/pull/13781))
- Modified Amazon Linux 2 SCA policy to resolve the rule and condition on control 1.5.2. ([#13950](https://github.com/wazuh/wazuh/pull/13950))

#### Removed

- Removed deprecated MITRE tags in rules. ([#13567](https://github.com/wazuh/wazuh/pull/13567))

### Other

#### Changed

- Fixed `test_agent_PUT_endpoints.tavern.yaml` API integration test failure in numbered branches. ([#13811](https://github.com/wazuh/wazuh/pull/13811))
- Upgraded external click and clickclick python dependencies to 8.1.3 and 20.10.2 respectively. ([13790]([https://github.com/wazuh/wazuh/pull/13790))


## [v4.3.4] - 2022-06-09

### Manager

#### Changed

- Integratord now tries to read alerts indefinitely, instead of performing 3 attempts. ([#13437](https://github.com/wazuh/wazuh/pull/13437))
- Adds a timeout for remote queries made by the Office 365, GitHub, and Agent Update modules. ([#13626](https://github.com/wazuh/wazuh/pull/13626))

#### Fixed

- Fixed bug in `agent_groups` CLI when removing agent groups. ([#13621](https://github.com/wazuh/wazuh/pull/13621))
- Fixed linux compilation errors with GCC 12. ([#13459](https://github.com/wazuh/wazuh/pull/13459))
- Fixed a crash in wazuh-analysisd when overwriting a rule with a configured active response. ([#13604](https://github.com/wazuh/wazuh/pull/13604))
- Fixed a crash in wazuh-db when it cannot open a database file. ([#13666](https://github.com/wazuh/wazuh/pull/13666))
- Fixed the vulnerability feed parsing mechanism, now truncates excessively long values (This problem was detected during Ubuntu Bionic feed update). ([#13566](https://github.com/wazuh/wazuh/pull/13566))
- Fixed a crash in wazuh-maild when parsing an alert with no full log and containing arrays of non-strings. [#13679](https://github.com/wazuh/wazuh/pull/13679))

### RESTful API

#### Fixed

- Updated default timeouts for `GET /mitre/software` and `GET /mitre/techniques` to avoid timing out in slow environments. ([#13550](https://github.com/wazuh/wazuh/pull/13550))

### Ruleset

#### Fixed

- Fixed the prematch criteria of `sshd-disconnect` decoder. ([#13560](https://github.com/wazuh/wazuh/pull/13560))


## [v4.3.3] - 2022-05-31

### Manager

#### Fixed

- Avoid creating duplicated client tags during deployment. ([#13651](https://github.com/wazuh/wazuh/pull/13651))

### Agent

#### Fixed

- Prevented Agentd from resetting its configuration on client block re-definition. ([#13642](https://github.com/wazuh/wazuh/pull/13642))


## [v4.3.2] - 2022-05-30

### Manager

#### Fixed

- Fixed a crash in Vuln Detector when scanning agents running on Windows. ([#13616](https://github.com/wazuh/wazuh/pull/13616))


## [v4.3.1] - 2022-05-18

### Manager

#### Fixed

- Fixed a crash when overwrite rules are triggered. ([#13439](https://github.com/wazuh/wazuh/pull/13439))
- Fixed a memory leak when loading overwrite rules. ([#13439](https://github.com/wazuh/wazuh/pull/13439))
- Fixed the use of relationship labels in overwrite rules. ([#13439](https://github.com/wazuh/wazuh/pull/13439))
- Fixed regex used to transform into datetime in the logtest framework function. ([#13430](https://github.com/wazuh/wazuh/pull/13430))

### RESTful API

#### Fixed

- Fixed API response when using sort in Agent upgrade related endpoints. ([#13178](https://github.com/wazuh/wazuh/pull/13178))

### Ruleset

#### Fixed

- Fixed rule 92656, added field condition win.eventdata.logonType equals 10 to avoid false positives. ([#13409](https://github.com/wazuh/wazuh/pull/13409))


## [v4.3.0] - 2022-05-05

### Manager

#### Added

- Added support for Arch Linux OS in Vulnerability Detector. Thanks to Aviel Warschawski (@avielw). ([#8178](https://github.com/wazuh/wazuh/pull/8178))
- Added a log message in the `cluster.log` file to notify that wazuh-clusterd has been stopped. ([#8749](https://github.com/wazuh/wazuh/pull/8749))
- Added message with the PID of `wazuh-clusterd` process when launched in foreground mode. ([#9077](https://github.com/wazuh/wazuh/pull/9077))
- Added time calculation when extra information is requested to the `cluster_control` binary. ([#10492](https://github.com/wazuh/wazuh/pull/10492))
- Added a context variable to indicate origin module in socket communication messages. ([#9209](https://github.com/wazuh/wazuh/pull/9209))
- Added unit tests for framework/core files to increase coverage. ([#9733](https://github.com/wazuh/wazuh/pull/9733))
- Added a verbose mode in the wazuh-logtest tool. ([#9204](https://github.com/wazuh/wazuh/pull/9204))
- Added Vulnerability Detector support for Amazon Linux. ([#8830](https://github.com/wazuh/wazuh/pull/8830))
- Introduced new option `<force>` to set the behavior when Authd finds conflicts on agent enrollment requests. ([#10693](https://github.com/wazuh/wazuh/pull/10693))
- Added saniziters to the unit tests execution. ([#9099](https://github.com/wazuh/wazuh/pull/9099))
- Vulnerability Detector introduces vulnerability inventory. ([#8237](https://github.com/wazuh/wazuh/pull/8237))
  - The manager will only deliver alerts when new vulnerabilities are detected in agents or when they stop applying.
- Added a mechanism to ensure the worker synchronization permissions is reset after a fixed period of time. ([#11031](https://github.com/wazuh/wazuh/pull/11031))
- Included mechanism to create and handle PID files for each child process of the API and cluster. ([#11799](https://github.com/wazuh/wazuh/pull/11799))
- Added support for Windows 11 in Vulnerability Detector. ([#12446](https://github.com/wazuh/wazuh/pull/12446))

#### Changed

- Changed the internal handling of agent keys in Remoted and Remoted to speed up key reloading. ([#8083](https://github.com/wazuh/wazuh/pull/8083))
- The option `<server>` of the Syslog output now supports hostname resolution. ([#7885](https://github.com/wazuh/wazuh/pull/7885))
- The product's UNIX user and group have been renamed to "wazuh". ([#7763](https://github.com/wazuh/wazuh/pull/7763))
- The MITRE database has been redesigned to provide full and searchable data. ([#7865](https://github.com/wazuh/wazuh/pull/7865))
- The static fields related to FIM have been ported to dynamic fields in Analysisd. ([7358](https://github.com/wazuh/wazuh/pull/7358))
- Changed all randomly generated IDs used for cluster tasks. Now, `uuid4` is used to ensure IDs are not repeated. ([8351](https://github.com/wazuh/wazuh/pull/8351))
- Improved sendsync error log to provide more details of the used parameters. ([#8873](https://github.com/wazuh/wazuh/pull/8873))
- Changed `walk_dir` function to be iterative instead of recursive. ([#9708](https://github.com/wazuh/wazuh/pull/9708))
- Refactored Integrity sync behavior so that new synchronizations do not start until extra-valid files are processed. ([#10183](https://github.com/wazuh/wazuh/issues/10038))
- Changed cluster synchronization, now the content of the `etc/shared` folder is synchronized. ([#10101](https://github.com/wazuh/wazuh/pull/10101))
- Changed all XML file loads. Now, `defusedxml` library is used to avoid possible XML-based attacks. ([8351](https://github.com/wazuh/wazuh/pull/8351))
- Changed configuration validation from execq socket to com socket. ([#8535](https://github.com/wazuh/wazuh/pull/8535))
- Updated utils unittest to improve process_array function coverage. ([#8392](https://github.com/wazuh/wazuh/pull/8392))
- Changed `request_slice` calculation to improve efficiency when accessing wazuh-db data. ([#8885](https://github.com/wazuh/wazuh/pull/8885))
- Improved the retrieval of information from `wazuh-db` so it reaches the optimum size in a single iteration. ([#9273](https://github.com/wazuh/wazuh/pull/9273))
- Optimized the way framework uses context cached functions and added a note on context_cached docstring. ([#9234](https://github.com/wazuh/wazuh/issues/9234))
- Improved framework regexes to be more specific and less vulnerable. ([#9332](https://github.com/wazuh/wazuh/pull/9332))
- Unified framework exceptions for non-active agents. ([#9423](https://github.com/wazuh/wazuh/pull/9423))
- Changed RBAC policies to case insensitive. ([#9433](https://github.com/wazuh/wazuh/pull/9433))
- Refactored framework stats module into SDK and core components to comply with Wazuh framework code standards. ([#9548](https://github.com/wazuh/wazuh/pull/9548))
- Changed the size of the agents chunks sent to the upgrade socket to make the upgrade endpoints faster. ([#10309](https://github.com/wazuh/wazuh/pull/10309))
- Refactored rootcheck and syscheck SDK code to make it clearer. ([#9408](https://github.com/wazuh/wazuh/pull/9408))
- Adapted Azure-logs module to use Microsoft Graph API instead of Active Directory Graph API. ([#9738](https://github.com/wazuh/wazuh/pull/9738))
- Analysisd now reconnects to Active Response if Remoted or Execd get restarted. ([#8060](https://github.com/wazuh/wazuh/pull/8060))
- Agent key polling now supports cluster environments. ([#10335](https://github.com/wazuh/wazuh/pull/10335))
- Extended support of Vulnerability Detector for Debian 11 (Bullseye). ([#10357](https://github.com/wazuh/wazuh/pull/10357))
- Improved Remoted performance with an agent TCP connection sending queue. ([#10326](https://github.com/wazuh/wazuh/pull/10326))
- Agent DB synchronization has been boosted by caching the last data checksum in Wazuh DB. ([#9093](https://github.com/wazuh/wazuh/pull/9093))
- Logtest now scans new ruleset files when loading a new session. ([#8892](https://github.com/wazuh/wazuh/pull/8892))
- CVE alerts by Vulnerability Detector now include the time of detection, severity, and score. ([#8237](https://github.com/wazuh/wazuh/pull/8237))
- Fixed manager startup when `<database_output>` is enabled. ([#10849](https://github.com/wazuh/wazuh/pull/10849))
- Improved cluster performance using multiprocessing.
  - Changed the cluster `local_integrity` task to run in a separate process to improve overall performance. ([#10767](https://github.com/wazuh/wazuh/pull/10767))
  - The cluster communication with the database for agent information synchronization runs in a parallel separate process. ([#10807](https://github.com/wazuh/wazuh/pull/10807))
  - The cluster processing of the extra-valid files in the master node is carried out in a parallel separate process. ([#10920](https://github.com/wazuh/wazuh/pull/10920))
  - The cluster's file compression task in the master node is carried out in a parallel separate process. ([#11328](https://github.com/wazuh/wazuh/pull/11328))
  - Now the processing of Integrity files in worker nodes is carried out in a parallel separate process ([#11364](https://github.com/wazuh/wazuh/pull/11364))
  - Use cluster and API single processing when the wazuh user doesn't have permissions to access `/dev/shm`. ([#11386](https://github.com/wazuh/wazuh/pull/11386))
- Changed the Ubuntu OVAL feed URL to security-metadata.canonical.com. ([#12491](https://github.com/wazuh/wazuh/pull/12491))
- Let Analysisd warn about missing rule dependencies instead of rejecting the ruleset. ([#12652](https://github.com/wazuh/wazuh/pull/12652))

#### Fixed

- Fixed a memory defect in Remoted when closing connection handles. ([#8223](https://github.com/wazuh/wazuh/pull/8223))
- Fixed a timing problem in the manager that might prevent Analysisd from sending Active responses to agents. ([#7625](https://github.com/wazuh/wazuh/pull/7625))
- Fixed a bug in Analysisd that did not apply field lookup in rules that overwrite other ones. ([#8210](https://github.com/wazuh/wazuh/pull/8210))
- Prevented the manager from leaving dangling agent database files. ([#8902](https://github.com/wazuh/wazuh/pull/8902))
- Corrected remediation message for error code 6004. ([#8254](https://github.com/wazuh/wazuh/pull/8254))
- Fixed a bug when deleting non-existing users or roles in the security SDK. ([#8157](https://github.com/wazuh/wazuh/pull/8157))
- Fixed a bug with `agent.conf` file permissions when creating an agent group. ([#8418](https://github.com/wazuh/wazuh/pull/8418))
- Fixed wrong exceptions with wdb pagination mechanism. ([#8422](https://github.com/wazuh/wazuh/pull/8422))
- Fixed error when loading some rules with the `\` character. ([#8747](https://github.com/wazuh/wazuh/pull/8747))
- Changed `WazuhDBQuery` class to properly close socket connections and prevent file descriptor leaks. ([#9216](https://github.com/wazuh/wazuh/pull/9216))
- Fixed error in the api configuration when using the `agent_upgrade` script. ([#10320](https://github.com/wazuh/wazuh/pull/10320))
- Handle `JSONDecodeError` in Distributed API class methods. ([#10341](https://github.com/wazuh/wazuh/pull/10341))
- Fixed an issue with duplicated logs in Azure-logs module and applied several improvements to it. ([#9738](https://github.com/wazuh/wazuh/pull/9738))
- Fixed the query parameter validation to allow usage of special chars in Azure module. ([#10680](https://github.com/wazuh/wazuh/pull/10680))
- Fix a bug running wazuh-clusterd process when it was already running. ([#8394](https://github.com/wazuh/wazuh/pull/8394))
- Allow cluster to send and receive messages with size higher than request_chunk. ([#8732](https://github.com/wazuh/wazuh/pull/8732))
- Fixed a bug that caused `wazuh-clusterd` process to not delete its pidfile when running in foreground mode and it is stopped. ([#9077](https://github.com/wazuh/wazuh/pull/9077))
- Fixed race condition due to lack of atomicity in the cluster synchronization mechanism. ([#10376](https://github.com/wazuh/wazuh/pull/10376))
- Fixed bug when displaying the dates of the cluster tasks that have not finished yet. Now `n/a` is displayed in these cases. ([#10492](https://github.com/wazuh/wazuh/pull/10492))
- Fixed missing field `value_type` in FIM alerts. ([#9196](https://github.com/wazuh/wazuh/pull/9196))
- Fixed a typo in the SSH Integrity Check script for Agentless. ([#9292](https://github.com/wazuh/wazuh/pull/9292))
- Fixed multiple race conditions in Remoted. ([#10421](https://github.com/wazuh/wazuh/pull/10421))
- The manager's agent database has been fixed to prevent dangling entries from removed agents. ([#10390](https://github.com/wazuh/wazuh/pull/10390))
- Fixed the alerts generated by FIM when a lookup operation on an SID fails. ([#9765](https://github.com/wazuh/wazuh/pull/9765))
- Fixed a bug that caused cluster agent-groups files to be synchronized multiple times unnecessarily. ([#10866](https://github.com/wazuh/wazuh/pull/10866))
- Fixed an issue in Wazuh DB that compiled the SQL statements multiple times unnecessarily. ([#10922](https://github.com/wazuh/wazuh/pull/10922))
- Fixed a crash in Analysisd when setting Active Response with agent_id = 0. ([#10948](https://github.com/wazuh/wazuh/pull/10948))
- Fixed an uninitialized Blowfish encryption structure warning. ([#11161](https://github.com/wazuh/wazuh/pull/11161))
- Fixed a memory overrun hazard in Vulnerability Detector. ([#11262](https://github.com/wazuh/wazuh/pull/11262))
- Fixed a bug when using a limit parameter higher than the total number of objects in the wazuh-db queries. ([#11282](https://github.com/wazuh/wazuh/pull/11282))
- Prevented a false positive for MySQL in Vulnerability Detector. ([#11440](https://github.com/wazuh/wazuh/pull/11440))
- Fixed segmentation fault in Analysisd when setting the number of queues to zero. ([#11448](https://github.com/wazuh/wazuh/pull/11448))
- Fixed false positives in Vulnerability Detector when scanning OVAl for Ubuntu Xenial and Bionic. ([#11440](https://github.com/wazuh/wazuh/pull/11440))
- Fixed an argument injection hazard in the Pagerduty integration script. Reported by Jose Maria Zaragoza (@JoseMariaZ). ([#11835](https://github.com/wazuh/wazuh/pull/11835))
- Fixed memory leaks in the feed parser at Vulnerability Detector. ([#11863](https://github.com/wazuh/wazuh/pull/11863))
  - Architecture data member from the RHEL 5 feed.
  - RHSA items containing no CVEs.
  - Unused RHSA data member when parsing Debian feeds.
- Prevented Authd from exiting due to a pipe signal if Wazuh DB gets closed. ([#12368](https://github.com/wazuh/wazuh/pull/12368))
- Fixed a buffer handling bug in Remoted that left the syslog TCP server stuck. ([#12415](https://github.com/wazuh/wazuh/pull/12415))
- Fixed a memory leak in Vulnerability Detector when discarding kernel packages. ([#12644](https://github.com/wazuh/wazuh/pull/12644))
- Fixed a memory leak at wazuh-logtest-legacy when matching a level-0 rule. ([#12655](https://github.com/wazuh/wazuh/pull/12655))
- Fixed a bug in the Vulnerability Detector CPE helper that may lead to produce false positives about Firefox ESR. ([#13067](https://github.com/wazuh/wazuh/pull/13067))

#### Removed

- The data reporting for Rootcheck scans in the agent_control tool has been deprecated. ([#8399](https://github.com/wazuh/wazuh/pull/8399))
- Removed old framework functions used to calculate agent status. ([#8846](https://github.com/wazuh/wazuh/pull/8846))

### Agent

#### Added

- Added an option to allow the agent to refresh the connection to the manager. ([#8016](https://github.com/wazuh/wazuh/pull/8016))
- Introduced a new module to collect audit logs from GitHub. ([#8532](https://github.com/wazuh/wazuh/pull/8532))
- FIM now expands wildcarded paths in the configuration on Windows agents. ([8461](https://github.com/wazuh/wazuh/pull/8461))
- FIM reloads wildcarded paths on full scans. ([8754](https://github.com/wazuh/wazuh/pull/8754))
- Added new `path_suffix` option to AWS module configuration. ([#8306](https://github.com/wazuh/wazuh/pull/8306))
- Added new `discard_regex` option to AWS module configuration. ([8331](https://github.com/wazuh/wazuh/pull/8331))
- Added support for the S3 Server Access bucket type in AWS module. ([#8482](https://github.com/wazuh/wazuh/pull/8442))
- Added support for Google Cloud Storage buckets using a new GCP module called `gcp-bucket`. ([#9119](https://github.com/wazuh/wazuh/pull/9119))
- Added support for VPC endpoints in AWS module. ([#9420](https://github.com/wazuh/wazuh/pull/9420))
- Added support for GCS access logs in the GCP module. ([#9279](https://github.com/wazuh/wazuh/pull/9279))
- Added an iam role session duration parameter to AWS module. ([#10198](https://github.com/wazuh/wazuh/pull/10198))
- Added support for variables in SCA policies. ([#8826](https://github.com/wazuh/wazuh/pull/8826))
- FIM now fills an audit rule file to support who-data although Audit is in immutable mode. ([#7721](https://github.com/wazuh/wazuh/pull/7721))
- Introduced an integration to collect audit logs from Office365. ([#8957](https://github.com/wazuh/wazuh/pull/8957))
- Added a new field `DisplayVersion` to Syscollector to help Vulnerability Detector match vulnerabilities for Windows. ([#10168](https://github.com/wazuh/wazuh/pull/10168))
- Added support for macOS agent upgrade via WPK. ([#10148](https://github.com/wazuh/wazuh/pull/10148))
- Added Logcollector support for macOS logs (Unified Logging System). ([#8632](https://github.com/wazuh/wazuh/pull/8632))

#### Changed

- The agent now reports the version of the running AIX operating system to the manager. ([#8381](https://github.com/wazuh/wazuh/pull/8381))
- Improved the reliability of the user ID parsing in FIM who-data mode on Linux. ([#8604](https://github.com/wazuh/wazuh/pull/8604))
- Extended support of Logcollector for MySQL 4.7 logs. Thanks to @YoyaYOSHIDA. ([#5047](https://github.com/wazuh/wazuh/pull/5047))
- Agents running on FreeBSD and OpenBSD now report their IP address. ([#9887](https://github.com/wazuh/wazuh/pull/9887))
- Reduced verbosity of FIM debugging logs. ([#8202](https://github.com/wazuh/wazuh/pull/8202))
- The agent's IP resolution frequency has been limited to prevent high CPU load. ([#9992](https://github.com/wazuh/wazuh/pull/9992))
- Syscollector has been optimized to use lees memory. ([#10236](https://github.com/wazuh/wazuh/pull/10236))
- Added support of ZscalerOS system information in the agent. ([#10337](https://github.com/wazuh/wazuh/pull/10337))
- Syscollector has been extended to collect missing Microsoft product hotfixes. ([#10259](https://github.com/wazuh/wazuh/pull/10259))
- Updated the osquery integration to find the new osqueryd location as of version 5.0. ([#10396](https://github.com/wazuh/wazuh/pull/10396))
- The internal FIM data handling has been simplified to find files by their path instead of their inode. ([#9123](https://github.com/wazuh/wazuh/pull/9123))
- Reimplemented the WPK installer rollback on Windows. ([#9764](https://github.com/wazuh/wazuh/pull/9764))
- Active responses for Windows agents now support native fields from Eventchannel. ([#10208](https://github.com/wazuh/wazuh/pull/10208))
- Error logs by Logcollector when a file is missing have been changed to info logs. ([#10651](https://github.com/wazuh/wazuh/pull/10651))
- The agent MSI installer for Windows now detects the platform version to install the default configuration. ([#8724](https://github.com/wazuh/wazuh/pull/8724))
- Agent logs for inability to resolve the manager hostname now have info level. ([#3659](https://github.com/wazuh/wazuh/pull/3659))
- Added ID number to connection enrollment logs. ([#11276](https://github.com/wazuh/wazuh/pull/11276))
- Standardized the use of the `only_logs_after` parameter in the external integration modules. ([#10838](https://github.com/wazuh/wazuh/pull/10838))
- Updated DockerListener integration shebang to python3 for Wazuh agents. ([#12150](https://github.com/wazuh/wazuh/pull/12150))
- Updated the Windows installer ico and png assets to the new logo. ([#12779](https://github.com/wazuh/wazuh/pull/12779))

#### Fixed

- Fixed a bug in FIM that did not allow monitoring new directories in real-time mode if the limit was reached at some point. ([#8784](https://github.com/wazuh/wazuh/pull/8784))
- Fixed a bug in FIM that threw an error when a query to the internal database returned no data. ([#8941](https://github.com/wazuh/wazuh/pull/8941))
- Fixed an error where the IP address was being returned along with the port for Amazon NLB service.([#8362](https://github.com/wazuh/wazuh/pull/8362))
- Fixed AWS module to properly handle the exception raised when processing a folder without logs. ([#8372](https://github.com/wazuh/wazuh/pull/8372)
- Fixed a bug with AWS module when pagination is needed in the bucket. ([#8433](https://github.com/wazuh/wazuh/pull/8433))
- Fixed an error with the ipGeoLocation field in AWS Macie logs. ([#8672](https://github.com/wazuh/wazuh/pull/8672))
- Changed an incorrect debug message in the GCloud integration module. ([#10333](https://github.com/wazuh/wazuh/pull/10333))
- Data race conditions have been fixed in FIM. ([#7848](https://github.com/wazuh/wazuh/pull/7848))
- Fixed wrong command line display in the Syscollector process report on Windows. ([#10011](https://github.com/wazuh/wazuh/pull/10011))
- Prevented Modulesd from freezing if Analysisd or Agentd get stopped before it. ([#10249](https://github.com/wazuh/wazuh/pull/10249))
- Fixed wrong keepalive message from the agent when file merged.mg is missing. ([#10405](https://github.com/wazuh/wazuh/pull/10405))
- Fixed missing logs from the Windows agent when it's getting stopped. ([#10381](https://github.com/wazuh/wazuh/pull/10381))
- Fixed missing packages reporting in Syscollector for macOS due to empty architecture data. ([#10524](https://github.com/wazuh/wazuh/pull/10524))
- Fixed FIM on Linux to parse audit rules with multiple keys for who-data. ([#7506](https://github.com/wazuh/wazuh/pull/7506))
- Fixed Windows 11 version collection in the agent. ([#10639](https://github.com/wazuh/wazuh/pull/10639))
- Fixed missing Eventchannel location in Logcollector configuration reporting. ([#10602](https://github.com/wazuh/wazuh/pull/10602))
- Updated CloudWatch Logs integration to avoid crashing when AWS raises Throttling errors. ([#10794](https://github.com/wazuh/wazuh/pull/10794))
- Fixed AWS modules' log file filtering when there are logs with and without a prefix mixed in a bucket. ([#10718](https://github.com/wazuh/wazuh/pull/10718))
- Fixed a bug on the installation script that made upgrades not to update the code of the external integration modules. ([#10884](https://github.com/wazuh/wazuh/pull/10884))
- Fixed issue with AWS integration module trying to parse manually created folders as if they were files. ([#10921](https://github.com/wazuh/wazuh/pull/10921))
- Fixed installation errors in OS with no subversion. ([#11086](https://github.com/wazuh/wazuh/pull/11086))
- Fixed a typo in an error log about enrollment SSL certificate. ([#11115](https://github.com/wazuh/wazuh/pull/11115))
- Fixed unit tests for Windows agent when built on MinGW 10. ([#11121](https://github.com/wazuh/wazuh/pull/11121))
- Fixed Windows agent compilation warnings. ([#10942](https://github.com/wazuh/wazuh/pull/10942))
- Fixed the OS version reported by the agent on OpenSUSE Tumbleweed. ([#11207](https://github.com/wazuh/wazuh/pull/11207))
- Prevented Syscollector from truncating the open port inode numbers on Linux. ([#11329](https://github.com/wazuh/wazuh/pull/11329))
- Fixed agent auto-restart on configuration changes when started via `wazuh-control` on a Systemd based Linux OS. ([#11365](https://github.com/wazuh/wazuh/pull/11365))
- Fixed a bug in the AWS module resulting in unnecessary API calls when trying to obtain the different Account IDs for the bucket. ([#10952](https://github.com/wazuh/wazuh/pull/10952))
- Fixed Azure integration's configuration parsing to allow omitting optional parameters. ([#11278](https://github.com/wazuh/wazuh/pull/11278))
- Fixed Azure Storage credentials validation bug. ([#11296](https://github.com/wazuh/wazuh/pull/11296))
- Fixed the read of the hostname in the installation process for openSUSE. ([#11455](https://github.com/wazuh/wazuh/pull/11455))
- Fixed the graceful shutdown when agent loses connection. ([#11425](https://github.com/wazuh/wazuh/pull/11425))
- Fixed error "Unable to set server IP address" on the Windows agent. ([#11736](https://github.com/wazuh/wazuh/pull/11736))
- Fixed reparse option in the AWS VPCFlow and Config integrations. ([#11608](https://github.com/wazuh/wazuh/pull/11608))
- Removed unnecessary calls to the AWS API made by the VPCFlow and Config integration modules. ([#11644](https://github.com/wazuh/wazuh/pull/11644))
- Fixed how the AWS Config module parses the dates used to request logs from AWS. ([#12324](https://github.com/wazuh/wazuh/pull/12324))
- Let Logcollector audit format parse logs with a custom name_format. ([#12676](https://github.com/wazuh/wazuh/pull/12676))
- Fixed Agent bootstrap issue that might lead to startup timeout when it cannot resolve a manager hostname. ([#12704](https://github.com/wazuh/wazuh/pull/12704))
- Fixed a bug in the agent's leaky bucket throughput regulator that could leave it stuck if the time is advanced on Windows. ([#13088](https://github.com/wazuh/wazuh/pull/13088))

#### Removed
- Removed oscap module files as it was already deprecated since v4.0.0. ([#10900](https://github.com/wazuh/wazuh/pull/10900))

### RESTful API

#### Added

- Added new `PUT /agents/reconnect` endpoint to force agents reconnection to the manager. ([#7988](https://github.com/wazuh/wazuh/pull/7988))
- Added `select` parameter to the `GET /security/users`, `GET /security/roles`, `GET /security/rules` and `GET /security/policies` endpoints. ([#6761](https://github.com/wazuh/wazuh/pull/6761))
- Added type and status filters to `GET /vulnerability/{agent_id}` endpoint. ([#8100](https://github.com/wazuh/wazuh/pull/8100))
- Added an option to configure SSL ciphers. ([#7490](https://github.com/wazuh/wazuh/pull/7490))
- Added an option to configure the maximum response time of the API. ([#8919](https://github.com/wazuh/wazuh/pull/8919))
- Added new `DELETE /rootcheck/{agent_id}` endpoint. ([#8945](https://github.com/wazuh/wazuh/pull/8945))
- Added new `GET /vulnerability/{agent_id}/last_scan` endpoint to check the latest vulnerability scan of an agent. ([#9028](https://github.com/wazuh/wazuh/pull/9028))
- Added new `cvss` and `severity` fields and filters to `GET /vulnerability/{agent_id}` endpoint. ([#9028](https://github.com/wazuh/wazuh/pull/9028))
- Added an option to configure the maximum allowed API upload size. ([#9100](https://github.com/wazuh/wazuh/pull/9100))
- Added new unit and integration tests for API models. ([#9142](https://github.com/wazuh/wazuh/pull/9142))
- Added message with the PID of `wazuh-apid` process when launched in foreground mode. ([#9077](https://github.com/wazuh/wazuh/pull/9077))
- Added `external id`, `source` and `url` to the MITRE endpoints responses. ([#9144](https://github.com/wazuh/wazuh/pull/9144))
- Added custom healthchecks for legacy agents in API integration tests, improving maintainability. ([#9297](https://github.com/wazuh/wazuh/pull/9297))
- Added new unit tests for the API python module to increase coverage. ([#9914](https://github.com/wazuh/wazuh/issues/9914))
- Added docker logs separately in API integration tests environment to get cleaner reports. ([#10238](https://github.com/wazuh/wazuh/pull/10238))
- Added new `disconnection_time` field to `GET /agents` response. ([#10437](https://github.com/wazuh/wazuh/pull/10437))
- Added new filters to agents upgrade endpoints. ([#10457](https://github.com/wazuh/wazuh/pull/10457))
- Added new API endpoints to access all the MITRE information. ([#8288](https://github.com/wazuh/wazuh/pull/8288))
- Show agent-info permissions flag when using cluster_control and in the `GET /cluster/healthcheck` API endpoint. ([#10947](https://github.com/wazuh/wazuh/pull/10947))
- Save agents' ossec.log if an API integration test fails. ([#11931](https://github.com/wazuh/wazuh/pull/11931))
- Added `POST /security/user/authenticate/run_as` endpoint to API bruteforce blocking system. ([#12085](https://github.com/wazuh/wazuh/pull/12085))
- Added new API endpoint to obtain summaries of agent vulnerabilities' inventory items. ([#12638](https://github.com/wazuh/wazuh/pull/12638))
- Added fields external_references, condition, title, published and updated to GET /vulnerability/{agent_id} API endpoint. ([#12727](https://github.com/wazuh/wazuh/pull/12727))
- Added the possibility to include strings in brackets in values of the `q` parameter. ([#13262](https://github.com/wazuh/wazuh/pull/13262]))

#### Changed

- Renamed SSL protocol configuration parameter. ([#7490](https://github.com/wazuh/wazuh/pull/7490))
- Reviewed and updated API spec examples and JSON body examples. ([#8827](https://github.com/wazuh/wazuh/pull/8827))
- Improved the performance of several API endpoints. This is specially appreciable in environments with a big number of agents.
  - Improved `PUT /agents/group` endpoint. ([#8937](https://github.com/wazuh/wazuh/pull/8937))
  - Improved `PUT /agents/restart` endpoint. ([#8938](https://github.com/wazuh/wazuh/pull/8938))
  - Improved `DELETE /agents` endpoint. ([#8950](https://github.com/wazuh/wazuh/pull/8950))
  - Improved `PUT /rootcheck` endpoint. ([#8959](https://github.com/wazuh/wazuh/pull/8959))
  - Improved `PUT /syscheck` endpoint. ([#8966](https://github.com/wazuh/wazuh/pull/8966))
  - Improved `DELETE /groups` endpoint and changed API response to be more consistent. ([#9046](https://github.com/wazuh/wazuh/pull/9046))
- Changed `DELETE /rootcheck` endpoint to `DELETE /experimental/rootcheck`. ([#8945](https://github.com/wazuh/wazuh/pull/8945))
- Reduced the time it takes for `wazuh-apid` process to check its configuration when using the `-t` parameter. ([#9012](https://github.com/wazuh/wazuh/pull/9012))
- Fixed malfunction in the `sort` parameter of syscollector endpoints. ([#9019](https://github.com/wazuh/wazuh/pull/9019))
- Improved API integration tests stability when failing in entrypoint. ([#9113](https://github.com/wazuh/wazuh/pull/9113))
- Made SCA API integration tests dynamic to validate responses coming from any agent version. ([#9228](https://github.com/wazuh/wazuh/pull/9228))
- Refactored and standardized all the date fields in the API responses to use ISO8601. ([#9227](https://github.com/wazuh/wazuh/pull/9227))
- Removed `Server` header from API HTTP responses. ([#9263](https://github.com/wazuh/wazuh/pull/9263))
- Improved JWT implementation by replacing HS256 signing algorithm with ES512. ([#9371](https://github.com/wazuh/wazuh/pull/9371))
- Removed limit of agents to upgrade using the API upgrade endpoints. ([#10009](https://github.com/wazuh/wazuh/pull/10009))
- Changed Windows agents FIM responses to return permissions as JSON. ([#10158](https://github.com/wazuh/wazuh/pull/10158))
- Adapted API endpoints to changes in `wazuh-authd` daemon `force` parameter. ([#10389](https://github.com/wazuh/wazuh/pull/10389))
- Deprecated `use_only_authd` API configuration option and related functionality. `wazuh-authd` will always be required for creating and removing agents. ([#10512](https://github.com/wazuh/wazuh/pull/10512))
- Improved API validators and related unit tests. ([#10745](https://github.com/wazuh/wazuh/pull/10745))
- Improved specific module healthchecks in API integration tests environment. ([#10905](https://github.com/wazuh/wazuh/pull/10905))
- Changed thread pool executors for process pool executors to improve API availability. ([#10916](https://github.com/wazuh/wazuh/pull/10916))
- Changed HTTPS options to use files instead of relative paths. ([#11410](https://github.com/wazuh/wazuh/pull/11410))

#### Fixed

- Fixed inconsistency in RBAC resources for `group:create`, `decoders:update`, and `rules:update` actions. ([#8196](https://github.com/wazuh/wazuh/pull/8196))
- Fixed the handling of an API error message occurring when Wazuh is started with a wrong `ossec.conf`. Now the execution continues and raises a warning. ([8378](https://github.com/wazuh/wazuh/pull/8378))
- Fixed a bug with `sort` parameter that caused a wrong response when sorting by several fields.([#8548](https://github.com/wazuh/wazuh/pull/8548))
- Fixed the description of `force_time` parameter in the API spec reference. ([#8597](https://github.com/wazuh/wazuh/issues/8597))
- Fixed API incorrect path in remediation message when maximum number of requests per minute is reached. ([#8537](https://github.com/wazuh/wazuh/pull/8537))
- Fixed agents' healthcheck error in the API integration test environment. ([#9071](https://github.com/wazuh/wazuh/pull/9071))
- Fixed a bug with `wazuh-apid` process handling of pidfiles when running in foreground mode. ([#9077](https://github.com/wazuh/wazuh/pull/9077))
- Fixed a bug with RBAC `group_id` matching. ([#9192](https://github.com/wazuh/wazuh/pull/9192))
- Removed temporal development keys and values from `GET /cluster/healthcheck` response. ([#9147](https://github.com/wazuh/wazuh/pull/9147))
- Fixed several errors when filtering by dates. ([#9227](https://github.com/wazuh/wazuh/pull/9227))
- Fixed limit in some endpoints like `PUT /agents/group/{group_id}/restart` and added a pagination method. ([#9262](https://github.com/wazuh/wazuh/pull/9262))
- Fixed bug with the `search` parameter resulting in invalid results. ([#9320](https://github.com/wazuh/wazuh/pull/9320))
- Fixed wrong values of `external_id` field in MITRE resources. ([#9368](https://github.com/wazuh/wazuh/pull/9368))
- Fixed how the API integration testing environment checks that `wazuh-apid` daemon is running before starting the tests. ([#9399](https://github.com/wazuh/wazuh/pull/9399))
- Add healthcheck to verify that `logcollector` stats are ready before starting the API integration test. ([#9777](https://github.com/wazuh/wazuh/pull/9777))
- Fixed API integration test healthcheck used in the `vulnerability` test cases. ([#10159](https://github.com/wazuh/wazuh/pull/10159))
- Fixed an error with `PUT /agents/node/{node_id}/restart` endpoint when no agents are present in selected node. ([#10179](https://github.com/wazuh/wazuh/pull/10179))
- Fixed RBAC experimental API integration tests expecting a 1760 code in implicit requests. ([#10322](https://github.com/wazuh/wazuh/pull/10322))
- Fixed cluster race condition that caused API integration test to randomly fail. ([#10289](https://github.com/wazuh/wazuh/pull/10289))
- Fixed `PUT /agents/node/{node_id}/restart` endpoint to exclude exception codes properly. ([#10619](https://github.com/wazuh/wazuh/pull/10619))
- Fixed `PUT /agents/group/{group_id}/restart` endpoint to exclude exception codes properly. ([#10666](https://github.com/wazuh/wazuh/pull/10666))
- Fixed agent endpoints `q` parameter to allow more operators when filtering by groups. ([#10656](https://github.com/wazuh/wazuh/pull/10656))
- Fixed API integration tests related to rule, decoder and task endpoints. ([#10830](https://github.com/wazuh/wazuh/pull/10830))
- Improved exceptions handling when starting the Wazuh API service. ([#11411](https://github.com/wazuh/wazuh/pull/11411))
- Fixed race condition while creating RBAC database. ([#11598](https://github.com/wazuh/wazuh/pull/11598))
- Fixed API integration tests failures caused by race conditions. ([#12102](https://github.com/wazuh/wazuh/pull/12102))

#### Removed

- Removed select parameter from GET /agents/stats/distinct endpoint. ([#8599](https://github.com/wazuh/wazuh/pull/8599))
- Removed `GET /mitre` endpoint. ([#8099](https://github.com/wazuh/wazuh/pull/8099))
- Deprecated the option to set log `path` in the configuration. ([#11410](https://github.com/wazuh/wazuh/pull/11410))

### Ruleset

#### Added

- Added Carbanak detection rules. ([#11306](https://github.com/wazuh/wazuh/pull/11306))
- Added Cisco FTD rules and decoders. ([#11309](https://github.com/wazuh/wazuh/pull/11309))
- Added decoders for AWS EKS service. ([#11284](https://github.com/wazuh/wazuh/pull/11284))
- Added F5 BIG IP ruleset. ([#11394](https://github.com/wazuh/wazuh/pull/11394))
- Added GCP VPC Storage, Firewall and Flow rules. ([#11191](https://github.com/wazuh/wazuh/pull/11191))
- Added Gitlab v12 ruleset. ([#11323](https://github.com/wazuh/wazuh/pull/11323))
- Added Microsoft Exchange Server rules and decoders. ([#11289](https://github.com/wazuh/wazuh/pull/11289))
- Added Microsoft Windows persistence by using registry keys detection. ([#11390](https://github.com/wazuh/wazuh/pull/11390))
- Added Oracle Database 12c rules and decoders. ([#11274](https://github.com/wazuh/wazuh/pull/11274))
- Added rules for Carbanak step 1.A - User Execution: Malicious File. ([#8476](https://github.com/wazuh/wazuh/pull/8476))
- Added rules for Carbanak step 2.A - Local Discovery. ([#11212](https://github.com/wazuh/wazuh/pull/11212))
- Added rules for Carbanak step 2.B - Screen Capture. ([#9075](https://github.com/wazuh/wazuh/pull/9075))
- Added rules for Carbanak step 5.B - Lateral Movement via SSH. ([#9097](https://github.com/wazuh/wazuh/pull/9097))
- Added rules for Carbanak step 9.A - User Monitoring. ([#11342](https://github.com/wazuh/wazuh/pull/11342))
- Added rules for Cloudflare WAF. ([#11373](https://github.com/wazuh/wazuh/pull/11373))
- Added ruleset for ESET Remote console. ([#11013](https://github.com/wazuh/wazuh/pull/11013))
- Added ruleset for GITHUB audit logs. ([#8532](https://github.com/wazuh/wazuh/pull/8532))
- Added ruleset for Palo Alto v8.X - v10.X. ([#11137](https://github.com/wazuh/wazuh/pull/11137))
- Added SCA policy for Amazon Linux 1. ([#11431](https://github.com/wazuh/wazuh/pull/11431))
- Added SCA policy for Amazon Linux 2. ([#11480](https://github.com/wazuh/wazuh/pull/11480))
- Added SCA policy for apple macOS 10.14 Mojave. ([#7035](https://github.com/wazuh/wazuh/pull/7035))
- Added SCA policy for apple macOS 10.15 Catalina. ([#7036](https://github.com/wazuh/wazuh/pull/7036))
- Added SCA policy for macOS Big Sur. ([#11454](https://github.com/wazuh/wazuh/pull/11454))
- Added SCA policy for Microsoft IIS 10. ([#11250](https://github.com/wazuh/wazuh/pull/11250))
- Added SCA policy for Microsoft SQL 2016. ([#11249](https://github.com/wazuh/wazuh/pull/11249))
- Added SCA policy for Mongo Database 3.6. ([#11247](https://github.com/wazuh/wazuh/pull/11247))
- Added SCA policy for NGINX. ([#11248](https://github.com/wazuh/wazuh/pull/11248))
- Added SCA policy for Oracle Database 19c. ([#11245](https://github.com/wazuh/wazuh/pull/11245))
- Added SCA policy for PostgreSQL 13. ([#11154](https://github.com/wazuh/wazuh/pull/11154))
- Added SCA policy for SUSE Linux Enterprise Server 15. ([#11223](https://github.com/wazuh/wazuh/pull/11223))
- Added SCA policy for Ubuntu 14. ([#11432](https://github.com/wazuh/wazuh/pull/11432))
- Added SCA policy for Ubuntu 16. ([#11452](https://github.com/wazuh/wazuh/pull/11452))
- Added SCA policy for Ubuntu 18. ([#11453](https://github.com/wazuh/wazuh/pull/11453))
- Added SCA policy for Ubuntu 20. ([#11430](https://github.com/wazuh/wazuh/pull/11430))
- Added SCA policy for. Solaris 11.4. ([#11286](https://github.com/wazuh/wazuh/pull/11286))
- Added Sophos UTM Firewall ruleset. ([#11122](https://github.com/wazuh/wazuh/pull/11122))
- Added Wazuh-api ruleset. ([#11357](https://github.com/wazuh/wazuh/pull/11357))

#### Changed

- Updated audit rules. ([#11016](https://github.com/wazuh/wazuh/pull/11016))
- Updated AWS s3 ruleset. ([#11177](https://github.com/wazuh/wazuh/pull/11177))
- Updated Exim 4 decoder and rules to latest format. ([#11344](https://github.com/wazuh/wazuh/pull/11344))
- Updated MITRE DB with latest MITRE JSON specification. ([#8738](https://github.com/wazuh/wazuh/pull/8738))
- Updated multiple rules to remove alert_by_email option. ([#11255](https://github.com/wazuh/wazuh/pull/11255))
- Updated NextCloud ruleset. ([#11795](https://github.com/wazuh/wazuh/pull/11795))
- Updated ProFTPD decoder. ([#11232](https://github.com/wazuh/wazuh/pull/11232))
- Updated RedHat Enterprise Linux 8 SCA up to version 1.0.1. ([#11242](https://github.com/wazuh/wazuh/pull/11242))
- Updated rules and decoders for FortiNet products. ([#11100](https://github.com/wazuh/wazuh/pull/11100))
- Updated SCA policy for CentOS 7. ([#11429](https://github.com/wazuh/wazuh/pull/11429))
- Updated SCA policy for CentOS 8. ([#8751](https://github.com/wazuh/wazuh/pull/8751))
- Updated SonicWall rules decoder. ([#11263](https://github.com/wazuh/wazuh/pull/11263))
- Updated SSHD ruleset. ([#11388](https://github.com/wazuh/wazuh/pull/11388))
- From file 0580-win-security_rules.xml, rules with id 60198 and 60199 are moved to file 0585-win-application_rules.xml, with rule ids 61071 and 61072 respectively. ([#8552](https://github.com/wazuh/wazuh/pull/8552))

#### Fixed

- Fixed bad character on rules 60908 and 60884 - win-application rules. ([#11117](https://github.com/wazuh/wazuh/pull/11117))
- Fixed Microsoft logs rules. ([#11369](https://github.com/wazuh/wazuh/pull/11369))
- Fixed PHP rules for MITRE and groups. ([#11405](https://github.com/wazuh/wazuh/pull/11405))
- Fixed rules id for Microsoft Windows Powershell. ([#11214](https://github.com/wazuh/wazuh/pull/11214))

### Other

#### Changed

- Upgraded external SQLite library dependency version to 3.36. ([#10247](https://github.com/wazuh/wazuh/pull/10247))
- Upgraded external BerkeleyDB library dependency version to 18.1.40. ([#10247](https://github.com/wazuh/wazuh/pull/10247))
- Upgraded external OpenSSL library dependency version to 1.1.1l. ([#10247](https://github.com/wazuh/wazuh/pull/10247))
- Upgraded external Google Test library dependency version to 1.11. ([#10927](https://github.com/wazuh/wazuh/pull/10927))
- Upgraded external Aiohttp library dependency version to 3.8.1. ([11436]([https://github.com/wazuh/wazuh/pull/11436))
- Upgraded external Werkzeug library dependency version to 2.0.2. ([11436]([https://github.com/wazuh/wazuh/pull/11436))
- Upgraded embedded Python version to 3.9.9. ([11436]([https://github.com/wazuh/wazuh/pull/11436))

#### Fixed

- Fixed error detection in the CURL helper library. ([#9168](https://github.com/wazuh/wazuh/pull/9168))
- Fixed external BerkeleyDB library support for GCC 11. ([#10899](https://github.com/wazuh/wazuh/pull/10899))
- Fixed an installation error due to missing OS minor version on CentOS Stream. ([#11086](https://github.com/wazuh/wazuh/pull/11086))
- Fixed an installation error due to missing command `hostname` on OpenSUSE Tumbleweed. ([#11455](https://github.com/wazuh/wazuh/pull/11455))


## [v4.2.7] - 2022-05-30

### Manager

#### Fixed

- Fixed a crash in Vuln Detector when scanning agents running on Windows (backport from 4.3.2). ([#13617](https://github.com/wazuh/wazuh/pull/13617))


## [v4.2.6] - 2022-03-29

### Manager

#### Fixed

- Fixed an integer overflow hazard in `wazuh-remoted` that caused it to drop incoming data after receiving 2^31 messages. ([#11974](https://github.com/wazuh/wazuh/pull/11974))


## [v4.2.5] - 2021-11-15

### Manager

#### Changed

- Active response requests for agents between v4.2.0 and v4.2.4 is now sanitized to prevent unauthorized code execution. ([#10809](https://github.com/wazuh/wazuh/pull/10809))

### Agent

#### Fixed

- A bug in the Active response tools that may allow unauthorized code execution has been mitigated. Reported by @rk700. ([#10809](https://github.com/wazuh/wazuh/pull/10809))


## [v4.2.4] - 2021-10-20

### Manager

#### Fixed

- Prevented files belonging to deleted agents from remaining in the manager. ([#9158](https://github.com/wazuh/wazuh/pull/9158))
- Fixed inaccurate agent group file cleanup in the database sync module. ([#10432](https://github.com/wazuh/wazuh/pull/10432))
- Prevented the manager from corrupting the agent data integrity when the disk gets full. ([#10479](https://github.com/wazuh/wazuh/pull/10479))
- Fixed a resource leak in Vulnerability Detector when scanning Windows agents. ([#10559](https://github.com/wazuh/wazuh/pull/10559))
- Stop deleting agent related files in cluster process when an agent is removed from `client.keys`. ([#9061](https://github.com/wazuh/wazuh/pull/9061))

## [v4.2.3] - 2021-10-06

### Manager

#### Fixed

- Fixed a bug in Remoted that might lead it to crash when retrieving an agent's group. ([#10388](https://github.com/wazuh/wazuh/pull/10388))


## [v4.2.2] - 2021-09-28

### Manager

#### Changed

- Clean up the agent's inventory data on the manager if Syscollector is disabled. ([#9133](https://github.com/wazuh/wazuh/pull/9133))
- Authd now refuses enrollment attempts if the agent already holds a valid key. ([#9779](https://github.com/wazuh/wazuh/pull/9779))

#### Fixed

- Fixed a false positive in Vulnerability Detector when packages have multiple conditions in the OVAL feed. ([#9647](https://github.com/wazuh/wazuh/pull/9647))
- Prevented pending agents from keeping their state indefinitely in the manager. ([#9042](https://github.com/wazuh/wazuh/pull/9042))
- Fixed Remoted to avoid agents in connected state with no group assignation. ([#9088](https://github.com/wazuh/wazuh/pull/9088))
- Fixed a bug in Analysisd that ignored the value of the rule option `noalert`. ([#9278](https://github.com/wazuh/wazuh/pull/9278))
- Fixed Authd's startup to set up the PID file before loading keys. ([#9378](https://github.com/wazuh/wazuh/pull/9378))
- Fixed a bug in Authd that delayed the agent timestamp update when removing agents. ([#9295](https://github.com/wazuh/wazuh/pull/9295))
- Fixed a bug in Wazuh DB that held wrong agent timestamp data. ([#9705](https://github.com/wazuh/wazuh/pull/9705))
- Fixed a bug in Remoted that kept deleted shared files in the multi-groups' merged.mg file. ([#9942](https://github.com/wazuh/wazuh/pull/9942))
- Fixed a bug in Analysisd that overwrote its queue socket when launched in test mode. ([#9987](https://github.com/wazuh/wazuh/pull/9987))
- Fixed a condition in the Windows Vulnerability Detector to prevent false positives when evaluating DU patches. ([#10016](https://github.com/wazuh/wazuh/pull/10016))
- Fixed a memory leak when generating the Windows report in Vulnerability Detector. ([#10214](https://github.com/wazuh/wazuh/pull/10214))
- Fixed a file descriptor leak in Analysisd when delivering an AR request to an agent. ([#10194](https://github.com/wazuh/wazuh/pull/10194))
- Fixed error with Wazuh path in Azure module. ([#10250](https://github.com/wazuh/wazuh/pull/10250))

### Agent

#### Changed

- Optimized Syscollector scan performance. ([#9907](https://github.com/wazuh/wazuh/pull/9907))
- Reworked the Google Cloud Pub/Sub integration module to increase the number of processed events per second allowing multithreading. Added new `num_threads` option to module configuration. ([#9927](https://github.com/wazuh/wazuh/pull/9927))
- Upgraded google-cloud-pubsub dependency to the latest stable version (2.7.1). ([#9964](https://github.com/wazuh/wazuh/pull/9964))
- Reimplemented the WPK installer rollback on Linux. ([#9443](https://github.com/wazuh/wazuh/pull/9443))
- Updated AWS WAF implementation to change `httpRequest.headers` field format. ([#10217](https://github.com/wazuh/wazuh/pull/10217))

#### Fixed

- Prevented the manager from hashing the shared configuration too often. ([#9710](https://github.com/wazuh/wazuh/pull/9710))
- Fixed a memory leak in Logcollector when re-subscribing to Windows Eventchannel. ([#9310](https://github.com/wazuh/wazuh/pull/9310))
- Fixed a memory leak in the agent when enrolling for the first time if it had no previous key. ([#9967](https://github.com/wazuh/wazuh/pull/9967))
- Removed CloudWatchLogs log stream limit when there are more than 50 log streams. ([#9934](https://github.com/wazuh/wazuh/pull/9934))
- Fixed a problem in the Windows installer that causes the agent to be unable to get uninstalled or upgraded. ([#9897](https://github.com/wazuh/wazuh/pull/9897))
- Fixed AWS WAF log parsing when there are multiple dicts in one line. ([#9775](https://github.com/wazuh/wazuh/pull/9775))
- Fixed a bug in AWS CloudWatch Logs module that caused already processed logs to be collected and reprocessed. ([#10024](https://github.com/wazuh/wazuh/pull/10024))
- Avoid duplicate alerts from case-insensitive 32-bit registry values in FIM configuration for Windows agents. ([#8256](https://github.com/wazuh/wazuh/pull/8256))
- Fixed a bug in the sources and WPK installer that made upgrade unable to detect the previous installation on CentOS 7. ([#10210](https://github.com/wazuh/wazuh/pull/10210))

### RESTful API

#### Changed

- Made SSL ciphers configurable and renamed SSL protocol option. ([#10219](https://github.com/wazuh/wazuh/pull/10219))

#### Fixed

- Fixed a bug with distributed API calls when the cluster is disabled. ([#9984](https://github.com/wazuh/wazuh/pull/9984))


## [v4.2.1] - 2021-09-03

### Fixed

- **Installer:**
  - Fixed a bug in the upgrade to 4.2.0 that disabled Eventchannel support on Windows agent. ([#9973](https://github.com/wazuh/wazuh/issues/9973))

- **Modules:**
  - Fixed a bug with Python-based integration modules causing the integrations to stop working in agents for Wazuh v4.2.0. ([#9975](https://github.com/wazuh/wazuh/issues/9975))


## [v4.2.0] - 2021-08-25

### Added

- **Core:**
  - Added support for bookmarks in Logcollector, allowing to follow the log file at the point where the agent stopped. ([#3368](https://github.com/wazuh/wazuh/issues/3368))
  - Improved support for multi-line logs with a variable number of lines in Logcollector. ([#5652](https://github.com/wazuh/wazuh/issues/5652))
  - Added an option to limit the number of files per second in FIM. ([#6830](https://github.com/wazuh/wazuh/pull/6830))
  - Added a statistics file to Logcollector. Such data is also available via API queries. ([#7109](https://github.com/wazuh/wazuh/pull/7109))
  - Allow statistical data queries to the agent. ([#7239](https://github.com/wazuh/wazuh/pull/7239))
  - Allowed quoting in commands to group arguments in the command wodle and SCA checks. ([#7307](https://github.com/wazuh/wazuh/pull/7307))
  - Let agents running on Solaris send their IP to the manager. ([#7408](https://github.com/wazuh/wazuh/pull/7408))
  - New option `<ip_update_interval>` to set how often the agent refresh its IP address. ([#7444](https://github.com/wazuh/wazuh/pull/7444))
  - Added support for testing location information in Wazuh Logtest. ([#7661](https://github.com/wazuh/wazuh/issues/7661))
  - Added Vulnerability Detector reports to Wazuh DB to know which CVE’s affect an agent. ([#7731](https://github.com/wazuh/wazuh/issues/7731))
  - Introduced an option to enable or disable listening Authd TLS port. ([#8755](https://github.com/wazuh/wazuh/pull/8755))

- **API:**
  - Added new endpoint to get agent stats from different components. ([#7200](https://github.com/wazuh/wazuh/pull/7200))
  - Added new endpoint to modify users' allow_run_as flag. ([#7588](https://github.com/wazuh/wazuh/pull/7588))
  - Added new endpoint to get vulnerabilities that affect an agent. ([#7647](https://github.com/wazuh/wazuh/pull/7647))
  - Added API configuration validator. ([#7803](https://github.com/wazuh/wazuh/pull/7803))
  - Added the capability to disable the max_request_per_minute API configuration option using 0 as value. ([#8115](https://github.com/wazuh/wazuh/pull/8115))

- **Ruleset:**
  - Decoders
    - Added support for UFW firewall to decoders. ([#7100](https://github.com/wazuh/wazuh/pull/7100))
    - Added Sophos firewall Decoders ([#7289](https://github.com/wazuh/wazuh/pull/7289))
    - Added Wazuh API Decoders ([#7289](https://github.com/wazuh/wazuh/pull/7289))
    - Added F5 BigIP Decoders. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
  - Rules
    - Added Sophos firewall Rules ([#7289](https://github.com/wazuh/wazuh/pull/7289))
    - Added Wazuh API Rules ([#7289](https://github.com/wazuh/wazuh/pull/7289))
    - Added Firewall Rules
    - Added F5 BigIp Rules. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
  - SCA
    - Added CIS policy "Ensure XD/NX support is enabled" back for SCA. ([#7316](https://github.com/wazuh/wazuh/pull/7316))
    - Added Apple MacOS 10.14 SCA ([#7035](https://github.com/wazuh/wazuh/pull/7035))
    - Added Apple MacOS 10.15 SCA ([#7036](https://github.com/wazuh/wazuh/pull/7036))
    - Added Apple MacOS 11.11 SCA ([#7037](https://github.com/wazuh/wazuh/pull/7037))

### Changed

- **Cluster:**
  - Improved the cluster nodes integrity calculation process. It only calculates the MD5 of the files that have been modified since the last integrity check. ([#8175](https://github.com/wazuh/wazuh/pull/8175))
  - Changed the synchronization of agent information between cluster nodes to complete the synchronization in a single task for each worker. ([#8182](https://github.com/wazuh/wazuh/pull/8182))
  - Changed cluster logs to show more useful information. ([#8002](https://github.com/wazuh/wazuh/pull/8002))

- **Core:**
  - Wazuh daemons have been renamed to a unified standard. ([#6912](https://github.com/wazuh/wazuh/pull/6912))
  - Wazuh CLIs have been renamed to a unified standard. ([#6903](https://github.com/wazuh/wazuh/pull/6903))
  - Wazuh internal directories have been renamed to a unified standard. ([#6920](https://github.com/wazuh/wazuh/pull/6920))
  - Prevent a condition in FIM that may lead to a memory error. ([#6759](https://github.com/wazuh/wazuh/pull/6759))
  - Let FIM switch to real-time mode for directories where who-data is not available (Audit in immutable mode). ([#6828](https://github.com/wazuh/wazuh/pull/6828))
  - Changed the Active Response protocol to receive messages in JSON format that include the full alert. ([#7317](https://github.com/wazuh/wazuh/pull/7317))
  - Changed references to the product name in logs. ([#7264](https://github.com/wazuh/wazuh/pull/7264))
  - Syscollector now synchronizes its database with the manager, avoiding full data delivery on each scan. ([#7379](https://github.com/wazuh/wazuh/pull/7379))
  - Remoted now supports both TCP and UDP protocols simultaneously. ([#7541](https://github.com/wazuh/wazuh/pull/7541))
  - Improved the unit tests for the os_net library. ([#7595](https://github.com/wazuh/wazuh/pull/7595))
  - FIM now removes the audit rules when their corresponding symbolic links change their target. ([#6999](https://github.com/wazuh/wazuh/pull/6999))
  - Compilation from sources now downloads the external dependencies prebuilt. ([#7797](https://github.com/wazuh/wazuh/pull/7797))
  - Added the old implementation of Logtest as `wazuh-logtest-legacy`. ([#7807](https://github.com/wazuh/wazuh/pull/7807))
  - Improved the performance of Analysisd when running on multi-core hosts. ([#7974](https://github.com/wazuh/wazuh/pull/7974))
  - Agents now report the manager when they stop. That allows the manager to log an alert and immediately set their state to "disconnected". ([#8021](https://github.com/wazuh/wazuh/pull/8021))
  - Wazuh building is now independent from the installation directory. ([#7327](https://github.com/wazuh/wazuh/pull/7327))
  - The embedded python interpreter is provided in a preinstalled, portable package. ([#7327](https://github.com/wazuh/wazuh/pull/7327))
  - Wazuh resources are now accessed by a relative path to the installation directory. ([#7327](https://github.com/wazuh/wazuh/pull/7327))
  - The error log that appeared when the agent cannot connect to SCA has been switched to warning. ([#8201](https://github.com/wazuh/wazuh/pull/8201))
  - The agent now validates the Audit connection configuration when enabling whodata for FIM on Linux. ([#8921](https://github.com/wazuh/wazuh/pull/8921))

- **API:**
  - Removed ruleset version from `GET /cluster/{node_id}/info` and `GET /manager/info` as it was deprecated. ([#6904](https://github.com/wazuh/wazuh/issues/6904))
  - Changed the `POST /groups` endpoint to specify the group name in a JSON body instead of in a query parameter. ([#6909](https://github.com/wazuh/wazuh/pull/6909))
  - Changed the `PUT /active-response` endpoint function to create messages with the new JSON format. ([#7312](https://github.com/wazuh/wazuh/pull/7312))
  - New parameters added to `DELETE /agents` endpoint and `older_than` field removed from response. ([#6366](https://github.com/wazuh/wazuh/issues/6366))
  - Changed login security controller to avoid errors in Restful API reference links. ([#7909](https://github.com/wazuh/wazuh/pull/7909))
  - Changed the PUT /agents/group/{group_id}/restart response format when there are no agents assigned to the group. ([#8123](https://github.com/wazuh/wazuh/pull/8123))
  - Agent keys used when adding agents are now obscured in the API log. ([#8149](https://github.com/wazuh/wazuh/pull/8149))
  - Improved all agent restart endpoints by removing active-response check. ([#8457](https://github.com/wazuh/wazuh/pull/8457))
  - Improved API requests processing time by applying cache to token RBAC permissions extraction. It will be invalidated if any resource related to the token is modified. ([#8615](https://github.com/wazuh/wazuh/pull/8615))
  - Increased to 100000 the maximum value accepted for `limit` API parameter, default value remains at 500. ([#8841](https://github.com/wazuh/wazuh/pull/8841))

- **Framework:**
  - Improved agent insertion algorithm when Authd is not available. ([#8682](https://github.com/wazuh/wazuh/pull/8682))

- **Ruleset:**
  - The ruleset was normalized according to the Wazuh standard. ([#6867](https://github.com/wazuh/wazuh/pull/6867))
  - Rules
    - Changed Ossec Rules. ([#7260](https://github.com/wazuh/wazuh/pull/7260))
    - Changed Cisco IOS Rules. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
    - Changed ID from 51000 to 51003 in Dropbear Rules. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
    - Changed 6 new rules for Sophos Rules. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
  - Decoders
    - Changed Active Response Decoders. ([#7317](https://github.com/wazuh/wazuh/pull/7317))
    - Changed Auditd Decoders. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
    - Changed Checkpoint Smart1 Decoders. ([#8676](https://github.com/wazuh/wazuh/pull/8676))
    - Changed Cisco ASA Decoders. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
    - Changed Cisco IOS Decoders. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
    - Changed Kernel Decoders. ([#7837](https://github.com/wazuh/wazuh/pull/7837))
    - Changed OpenLDAP Decoders. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
    - Changed Ossec Decoders. ([#7260](https://github.com/wazuh/wazuh/pull/7260))
    - Changed Sophos Decoders. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
    - Changed PFsense Decoders. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
    - Changed Panda PAPS Decoders. ([#8676](https://github.com/wazuh/wazuh/pull/8676))


- **External dependencies:**
  - Upgrade boto3, botocore, requests, s3transfer and urllib3 Python dependencies to latest stable versions. ([#8886](https://github.com/wazuh/wazuh/pull/8886))
  - Update Python to latest stable version (3.9.6). ([#9389](https://github.com/wazuh/wazuh/pull/9389))
  - Upgrade GCP dependencies and pip to latest stable version.
  - Upgrade python-jose to 3.1.0.
  - Add tabulate dependency.

### Fixed

- **Cluster:**
  - Fixed memory usage when creating cluster messages. ([#6736](https://github.com/wazuh/wazuh/pull/6736))
  - Fixed a bug when unpacking incomplete headers in cluster messages. ([#8142](https://github.com/wazuh/wazuh/pull/8142))
  - Changed error message to debug when iterating a file listed that is already deleted. ([#8499](https://github.com/wazuh/wazuh/pull/8499))
  - Fixed cluster timeout exceptions. ([#8901](https://github.com/wazuh/wazuh/pull/8901))
  - Fixed unhandled KeyError when an error command is received in any cluster node. ([#8872](https://github.com/wazuh/wazuh/pull/8872))
  - Fixed unhandled cluster error in send_string() communication protocol. ([#8943](https://github.com/wazuh/wazuh/pull/8943))

- **Core:**
  - Fixed a bug in FIM when setting scan_time to "12am" or "12pm". ([#6934](https://github.com/wazuh/wazuh/pull/6934))
  - Fixed a bug in FIM that produced wrong alerts when the file limit was reached. ([#6802](https://github.com/wazuh/wazuh/pull/6802))
  - Fixed a bug in Analysisd that reserved the static decoder field name "command" but never used it. ([#7105](https://github.com/wazuh/wazuh/pull/7105))
  - Fixed evaluation of fields in the tag `<description>` of rules. ([#7073](https://github.com/wazuh/wazuh/pull/7073))
  - Fixed bugs in FIM that caused symbolic links to not work correctly. ([#6789](https://github.com/wazuh/wazuh/pull/6789))
  - Fixed path validation in FIM configuration. ([#7018](https://github.com/wazuh/wazuh/pull/7018))
  - Fixed a bug in the "ignore" option on FIM where relative paths were not resolved. ([#7018](https://github.com/wazuh/wazuh/pull/7018))
  - Fixed a bug in FIM that wrongly detected that the file limit had been reached. ([#7268](https://github.com/wazuh/wazuh/pull/7268))
  - Fixed a bug in FIM that did not produce alerts when a domain user deleted a file. ([#7265](https://github.com/wazuh/wazuh/pull/7265))
  - Fixed Windows agent compilation with GCC 10. ([#7359](https://github.com/wazuh/wazuh/pull/7359))
  - Fixed a bug in FIM that caused to wrongly expand environment variables. ([#7332](https://github.com/wazuh/wazuh/pull/7332))
  - Fixed the inclusion of the rule description in archives when matched a rule that would not produce an alert. ([#7476](https://github.com/wazuh/wazuh/pull/7476))
  - Fixed a bug in the regex parser that did not accept empty strings. ([#7495](https://github.com/wazuh/wazuh/pull/7495))
  - Fixed a bug in FIM that did not report deleted files set with real-time in agents on Solaris. ([#7414](https://github.com/wazuh/wazuh/pull/7414))
  - Fixed a bug in Remoted that wrongly included the priority header in syslog when using TCP. ([#7633](https://github.com/wazuh/wazuh/pull/7633))
  - Fixed a stack overflow in the XML parser by limiting 1024 levels of recursion. ([#7782](https://github.com/wazuh/wazuh/pull/7782))
  - Prevented Vulnerability Detector from scanning all the agents in the master node that are connected to another worker. ([#7795](https://github.com/wazuh/wazuh/pull/7795))
  - Fixed an issue in the database sync module that left dangling agent group files. ([#7858](https://github.com/wazuh/wazuh/pull/7858))
  - Fixed memory leaks in the regex parser in Analysisd. ([#7919](https://github.com/wazuh/wazuh/pull/7919))
  - Fixed a typo in the initial value for the hotfix scan ID in the agents' database schema. ([#7905](https://github.com/wazuh/wazuh/pull/7905))
  - Fixed a segmentation fault in Vulnerability Detector when parsing an unsupported package version format. ([#8003](https://github.com/wazuh/wazuh/pull/8003))
  - Fixed false positives in FIM when the inode of multiple files change, due to file inode collisions in the engine database. ([#7990](https://github.com/wazuh/wazuh/pull/7990))
  - Fixed the error handling when wildcarded Redhat feeds are not found. ([#6932](https://github.com/wazuh/wazuh/pull/6932))
  - Fixed the `equals` comparator for OVAL feeds in Vulnerability Detector. ([#7862](https://github.com/wazuh/wazuh/pull/7862))
  - Fixed a bug in FIM that made the Windows agent crash when synchronizing a Windows Registry value that starts with a colon (`:`). ([#8098](https://github.com/wazuh/wazuh/pull/8098) [#8143](https://github.com/wazuh/wazuh/pull/8143))
  - Fixed a starving hazard in Wazuh DB that might stall incoming requests during the database commitment. ([#8151](https://github.com/wazuh/wazuh/pull/8151))
  - Fixed a race condition in Remoted that might make it crash when closing RID files. ([#8224](https://github.com/wazuh/wazuh/pull/8224))
  - Fixed a descriptor leak in the agent when failed to connect to Authd. ([#8789](https://github.com/wazuh/wazuh/pull/8789))
  - Fixed a potential error when starting the manager due to a delay in the creation of Analysisd PID file. ([#8828](https://github.com/wazuh/wazuh/pull/8828))
  - Fixed an invalid memory access hazard in Vulnerability Detector. ([#8551](https://github.com/wazuh/wazuh/pull/8551))
  - Fixed an error in the FIM decoder at the manager when the agent reports a file with an empty ACE list. ([#8571](https://github.com/wazuh/wazuh/pull/8571))
  - Prevented the agent on macOS from getting corrupted after an operating system upgrade. ([#8620](https://github.com/wazuh/wazuh/pull/8620))
  - Fixed an error in the manager that could not check its configuration after a change by the API when Active response is disabled. ([#8357](https://github.com/wazuh/wazuh/pull/8357))
  - Fixed a problem in the manager that left remote counter and agent group files when removing an agent. ([#8630](https://github.com/wazuh/wazuh/pull/8630))
  - Fixed an error in the agent on Windows that could corrupt the internal FIM databas due to disabling the disk sync. ([#8905](https://github.com/wazuh/wazuh/pull/8905))
  - Fixed a crash in Logcollector on Windows when handling the position of the file. ([#9364](https://github.com/wazuh/wazuh/pull/9364))
  - Fixed a buffer underflow hazard in Remoted when handling input messages. Thanks to Johannes Segitz (@jsegitz). ([#9285](https://github.com/wazuh/wazuh/pull/9285))
  - Fixed a bug in the agent that tried to verify the WPK CA certificate even when verification was disabled. ([#9547](https://github.com/wazuh/wazuh/pull/9547))

- **API:**
  - Fixed wrong API messages returned when getting agents' upgrade results. ([#7587](https://github.com/wazuh/wazuh/pull/7587))
  - Fixed wrong `user` string in API logs when receiving responses with status codes 308 or 404. ([#7709](https://github.com/wazuh/wazuh/pull/7709))
  - Fixed API errors when cluster is disabled and node_type is worker. ([#7867](https://github.com/wazuh/wazuh/pull/7867))
  - Fixed redundant paths and duplicated tests in API integration test mapping script. ([#7798](https://github.com/wazuh/wazuh/pull/7798))
  - Fixed an API integration test case failing in test_rbac_white_all and added a test case for the enable/disable run_as endpoint.([8014](https://github.com/wazuh/wazuh/pull/8014))
  - Fixed a thread race condition when adding or deleting agents without authd ([8148](https://github.com/wazuh/wazuh/pull/8148))
  - Fixed CORS in API configuration. ([#8496](https://github.com/wazuh/wazuh/pull/8496))
  - Fixed api.log to avoid unhandled exceptions on API timeouts. ([#8887](https://github.com/wazuh/wazuh/pull/8887))

- **Ruleset:**
  - Fixed usb-storage-attached regex pattern to support blank spaces. ([#7837](https://github.com/wazuh/wazuh/issues/7837))
  - Fixed SCA checks for RHEL7 and CentOS 7. Thanks to J. Daniel Medeiros (@jdmedeiros). ([#7645](https://github.com/wazuh/wazuh/pull/7645))
  - Fixed the match criteria of the AWS WAF rules. ([#8111](https://github.com/wazuh/wazuh/pull/8111))
  - Fixed sample log in sudo decoders.
  - Fixed Pix Decoders match regex. ([#7485](https://github.com/wazuh/wazuh/pull/7495))
  - Fixed regex in Syslog Rules. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
  - Fixed category in PIX Rules. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
  - Fixed authentication tag in group for MSauth Rules. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
  - Fixed match on Nginx Rules. ([#7122](https://github.com/wazuh/wazuh/pull/7122))
  - Fixed sample log on Netscaler Rules. ([#7783](https://github.com/wazuh/wazuh/pull/7783))
  - Fixed match field for rules 80441 and 80442 in Amazon Rules. ([#8111](https://github.com/wazuh/wazuh/pull/8111))
  - Fixed sample logs in Owncloud Rules. ([#7122](https://github.com/wazuh/wazuh/pull/7122))
  - Fixed authentication tag in group for Win Security Rules. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
  - Fixed sample log in Win Security Rules. ([#7783](https://github.com/wazuh/wazuh/pull/7783))
  - Fixed sample log in Win Application Rules. ([#7783](https://github.com/wazuh/wazuh/pull/7783))
  - Fixed mitre block in Paloalto Rules. ([#7783](https://github.com/wazuh/wazuh/pull/7783))

- **Modules:**
  - Fixed an error when trying to use a non-default aws profile with CloudWatchLogs ([#9331](https://github.com/wazuh/wazuh/pull/9331))

### Removed

- **Core:**
  - File /etc/ossec-init.conf does not exist anymore. ([#7175](https://github.com/wazuh/wazuh/pull/7175))
  - Unused files have been removed from the repository, including TAP tests. ([#7398](https://github.com/wazuh/wazuh/issues/7398))

- **API:**
  - Removed the `allow_run_as` parameter from endpoints `POST /security/users` and `PUT /security/users/{user_id}`. ([#7588](https://github.com/wazuh/wazuh/pull/7588))
  - Removed `behind_proxy_server` option from configuration. ([#7006](https://github.com/wazuh/wazuh/issues/7006))

- **Framework:**
  - Deprecated `update_ruleset` script. ([#6904](https://github.com/wazuh/wazuh/issues/6904))

- **Ruleset**
  - Removed rule 51004 from Dropbear Rules. ([#7289](https://github.com/wazuh/wazuh/pull/7289))
  - Remuved rules 23508, 23509 and 23510 from Vulnerability Detector Rules.

## [v4.1.5] - 2021-04-22

### Fixed

- **Core:**
  - Fixed a bug in Vulnerability Detector that made Modulesd crash while updating the NVD feed due to a missing CPE entry. ([4cbd1e8](https://github.com/wazuh/wazuh/commit/4cbd1e85eeee0eb0d8247fa7228f590a9dd24153))


## [v4.1.4] - 2021-03-25

### Fixed

- **Cluster:**
  - Fixed workers reconnection after restarting master node. Updated `asyncio.Task.all_tasks` method removed in Python 3.9. ([#8017](https://github.com/wazuh/wazuh/pull/8017))


## [v4.1.3] - 2021-03-23

### Changed

- **External dependencies:**
  - Upgraded Python version from 3.8.6 to 3.9.2 and several Python dependencies. ([#7943](https://github.com/wazuh/wazuh/pull/7943))

### Fixed

- **Core:**
  - Fixed an error in FIM when getting the files' modification time on Windows due to wrong permission flags. ([#7870](https://github.com/wazuh/wazuh/pull/7870))
  - Fixed a bug in Wazuh DB that truncated the output of the agents' status query towards the cluster. ([#7873](https://github.com/wazuh/wazuh/pull/7873))

- **API:**
  - Fixed validation for absolute and relative paths. ([#7906](https://github.com/wazuh/wazuh/pull/7906))


## [v4.1.2] - 2021-03-08

### Changed

- **Core:**
  - The default value of the agent disconnection time option has been increased to 10 minutes. ([#7744](https://github.com/wazuh/wazuh/pull/7744))
  - The warning log from Remoted about sending messages to disconnected agents has been changed to level-1 debug log. ([#7755](https://github.com/wazuh/wazuh/pull/7755))

- **API:**
  - API logs showing request parameters and body will be generated with API log level `info` instead of `debug`. ([#7735](https://github.com/wazuh/wazuh/issues/7735))

- **External dependencies:**
  - Upgraded aiohttp version from 3.6.2 to 3.7.4. ([#7734](https://github.com/wazuh/wazuh/pull/7734))

### Fixed

- **Core:**
  - Fix a bug in the unit tests that randomly caused false failures. ([#7723](https://github.com/wazuh/wazuh/pull/7723))
  - Fixed a bug in the Analysisd configuration that did not apply the setting `json_null_fields`. ([#7711](https://github.com/wazuh/wazuh/pull/7711))
  - Fixed the checking of the option `ipv6` in Remoted. ([#7737](https://github.com/wazuh/wazuh/pull/7737))
  - Fixed the checking of the option `rids_closing_time` in Remoted. ([#7746](https://github.com/wazuh/wazuh/pull/7746))


## [v4.1.1] - 2021-02-25

### Added

- **External dependencies:**
  - Added cython (0.29.21) library to Python dependencies. ([#7451](https://github.com/wazuh/wazuh/pull/7451))
  - Added xmltodict (0.12.0) library to Python dependencies. ([#7303](https://github.com/wazuh/wazuh/pull/7303))

- **API:**
  - Added new endpoints to manage rules files. ([#7178](https://github.com/wazuh/wazuh/issues/7178))
  - Added new endpoints to manage CDB lists files. ([#7180](https://github.com/wazuh/wazuh/issues/7180))
  - Added new endpoints to manage decoder files. ([#7179](https://github.com/wazuh/wazuh/issues/7179))
  - Added new manager and cluster endpoints to update Wazuh configuration (ossec.conf). ([#7181](https://github.com/wazuh/wazuh/issues/7181))

### Changed

- **External dependencies:**
  - Upgraded Python version from 3.8.2 to 3.8.6. ([#7451](https://github.com/wazuh/wazuh/pull/7451))
  - Upgraded Cryptography python library from 3.2.1 to 3.3.2. ([#7451](https://github.com/wazuh/wazuh/pull/7451))
  - Upgraded cffi python library from 1.14.0 to 1.14.4. ([#7451](https://github.com/wazuh/wazuh/pull/7451))

- **API:**
  - Added raw parameter to GET /manager/configuration and GET cluster/{node_id}/configuration to load ossec.conf in xml format. ([#7565](https://github.com/wazuh/wazuh/issues/7565))

### Fixed

- **API:**
  - Fixed an error with the RBAC permissions in the `GET /groups` endpoint. ([#7328](https://github.com/wazuh/wazuh/issues/7328))
  - Fixed a bug with Windows registries when parsing backslashes. ([#7309](https://github.com/wazuh/wazuh/pull/7309))
  - Fixed an error with the RBAC permissions when assigning multiple `agent:group` resources to a policy. ([#7393](https://github.com/wazuh/wazuh/pull/7393))
  - Fixed an error with search parameter when using special characters. ([#7301](https://github.com/wazuh/wazuh/pull/7301))
- **AWS Module:**
  - Fixed a bug that caused an error when attempting to use an IAM Role with **CloudWatchLogs** service. ([#7330](https://github.com/wazuh/wazuh/pull/7330))
- **Framework:**
  - Fixed a race condition bug when using RBAC expand_group function. ([#7353](https://github.com/wazuh/wazuh/pull/7353))
  - Fix migration process to overwrite default RBAC policies. ([#7594](https://github.com/wazuh/wazuh/pull/7594))
- **Core:**
  - Fixed a bug in Windows agent that did not honor the buffer's EPS limit. ([#7333](https://github.com/wazuh/wazuh/pull/7333))
  - Fixed a bug in Integratord that might lose alerts from Analysisd due to a race condition. ([#7338](https://github.com/wazuh/wazuh/pull/7338))
  - Silence the error message when the Syslog forwarder reads an alert with no rule object. ([#7539](https://github.com/wazuh/wazuh/pull/7539))
  - Fixed a memory leak in Vulnerability Detector when updating NVD feeds. ([#7559](https://github.com/wazuh/wazuh/pull/7559))
  - Prevent FIM from raising false positives about group name changes due to a thread unsafe function. ([#7589](https://github.com/wazuh/wazuh/pull/7589))

### Removed

- **API:**
  - Deprecated /manager/files and /cluster/{node_id}/files endpoints. ([#7209](https://github.com/wazuh/wazuh/issues/7209))


## [v4.1.0] - 2021-02-15

### Added

- **Core:**
  - Allow negation of expressions in rules. ([#6258](https://github.com/wazuh/wazuh/pull/6258))
  - Support for PCRE2 regular expressions in rules and decoders. ([#6480](https://github.com/wazuh/wazuh/pull/6480))
  - Added new **ruleset test module**. Allow testing and verification of rules and decoders using Wazuh User Interface. ([#5337](https://github.com/wazuh/wazuh/issues/5337))
  - Added new **upgrade module**. WPK upgrade feature has been moved to this module, which offers support for cluster architecture and simultaneous upgrades. ([#5387](https://github.com/wazuh/wazuh/issues/5387))
  - Added new **task module**. This module stores and manages all the tasks that are executed in the agents or managers. ([#5386](https://github.com/wazuh/wazuh/issues/5386))
  - Let the time interval to detect that an agent got disconnected configurable. Deprecate parameter `DISCON_TIME`. ([#6396](https://github.com/wazuh/wazuh/pull/6396))
  - Added support to macOS in Vulnerability Detector. ([#6532](https://github.com/wazuh/wazuh/pull/6532))
  - Added the capability to perform FIM on values in the Windows Registry. ([#6735](https://github.com/wazuh/wazuh/pull/6735))
- **API:**
  - Added endpoints to query and manage Rootcheck data. ([#6496](https://github.com/wazuh/wazuh/pull/6496))
  - Added new endpoint to check status of tasks. ([#6029](https://github.com/wazuh/wazuh/issues/6029))
  - Added new endpoints to run the logtest tool and delete a logtest session. ([#5984](https://github.com/wazuh/wazuh/pull/5984))
  - Added debug2 mode for API log and improved debug mode. ([#6822](https://github.com/wazuh/wazuh/pull/6822))
  - Added missing secure headers for API responses. ([#7024](https://github.com/wazuh/wazuh/issues/7024))
  - Added new config option to disable uploading configurations containing remote commands. ([#7016](https://github.com/wazuh/wazuh/issues/7016))
- **AWS Module:**
  - Added support for AWS load balancers (Application Load Balancer, Classic Load Balancer and Network Load Balancer). ([#6034](https://github.com/wazuh/wazuh/issues/6034))
- **Framework:**
  - Added new framework modules to use the logtest tool. ([#5870](https://github.com/wazuh/wazuh/pull/5870))
  - Improved `q` parameter on rules, decoders and cdb-lists modules to allow multiple nested fields. ([#6560](https://github.com/wazuh/wazuh/pull/6560))

### Changed

- **Core:**
  - Removed the limit of agents that a manager can support. ([#6097](https://github.com/wazuh/wazuh/issues/6097))
    - Migration of rootcheck results to Wazuh DB to remove the files with the results of each agent. ([#6096](https://github.com/wazuh/wazuh/issues/6096))
    - Designed new mechanism to close RIDS files when agents are disconnected. ([#6112](https://github.com/wazuh/wazuh/issues/6112))
  - Moved CA configuration section to verify WPK signatures from `active-response` section to `agent-upgrade` section. ([#5929](https://github.com/wazuh/wazuh/issues/5929))
  - The tool ossec-logtest has been renamed to wazuh-logtest, and it uses a new testing service integrated in Analysisd. ([#6103](https://github.com/wazuh/wazuh/pull/6103))
  - Changed error message to debug when multiple daemons attempt to remove an agent simultaneously ([#6185](https://github.com/wazuh/wazuh/pull/6185))
  - Changed error message to warning when the agent fails to reach a module. ([#5817](https://github.com/wazuh/wazuh/pull/5817))
- **API:**
  - Changed the `status` parameter behavior in the `DELETE /agents` endpoint to enhance security. ([#6829](https://github.com/wazuh/wazuh/pull/6829))
  - Changed upgrade endpoints to accept a list of agents, maximum 100 agents per request. ([#5336](https://github.com/wazuh/wazuh/issues/5536))
  - Improved input validation regexes for `names` and `array_names`. ([#7015](https://github.com/wazuh/wazuh/issues/7015))
- **Framework:**
  - Refactored framework to work with new upgrade module. ([#5537](https://github.com/wazuh/wazuh/issues/5537))
  - Refactored agent upgrade CLI to work with new ugprade module. It distributes petitions in a clustered environment. ([#5675](https://github.com/wazuh/wazuh/issues/5675))
  - Changed rule and decoder details structure to support PCRE2. ([#6318](https://github.com/wazuh/wazuh/issues/6318))
  - Changed access to agent's status. ([#6326](https://github.com/wazuh/wazuh/issues/6326))
  - Improved AWS Config integration to avoid performance issues by removing alert fields with variables such as Instance ID in its name. ([#6537](https://github.com/wazuh/wazuh/issues/6537))

### Fixed

- **Core:**
  - Fixed error in Analysisd when getting the ossec group ID. ([#6688](https://github.com/wazuh/wazuh/pull/6688))
  - Prevented FIM from reporting configuration error when setting patterns that match no files. ([#6187](https://github.com/wazuh/wazuh/pull/6187))
  - Fixed the array parsing when building JSON alerts. ([#6687](https://github.com/wazuh/wazuh/pull/6687))
  - Added Firefox ESR to the CPE helper to distinguish it from Firefox when looking for vulnerabilities. ([#6610](https://github.com/wazuh/wazuh/pull/6610))
  - Fixed the evaluation of packages from external sources with the official vendor feeds in Vulnerability Detector. ([#6611](https://github.com/wazuh/wazuh/pull/6611))
  - Fixed the handling of duplicated tags in the Vulnerability Detector configuration. ([#6683](https://github.com/wazuh/wazuh/pull/6683))
  - Fixed the validation of hotfixes gathered by Syscollector. ([#6706](https://github.com/wazuh/wazuh/pull/6706))
  - Fixed the reading of the Linux OS version when `/etc/os-release` doesn't provide it. ([#6674](https://github.com/wazuh/wazuh/pull/6674))
  - Fixed a false positive when comparing the minor target of CentOS packages in Vulnerability Detector. ([#6709](https://github.com/wazuh/wazuh/pull/6709))
  - Fixed a zombie process leak in Modulesd when using commands without a timeout. ([#6719](https://github.com/wazuh/wazuh/pull/6719))
  - Fixed a race condition in Remoted that might create agent-group files with wrong permissions. ([#6833](https://github.com/wazuh/wazuh/pull/6833))
  - Fixed a warning log in Wazuh DB when upgrading the global database. ([#6697](https://github.com/wazuh/wazuh/pull/6697))
  - Fixed a bug in FIM on Windows that caused false positive due to changes in the host timezone or the daylight saving time when monitoring files in a FAT32 filesystem. ([#6801](https://github.com/wazuh/wazuh/pull/6801))
  - Fixed the purge of the Redhat vulnerabilities database before updating it. ([#7050](https://github.com/wazuh/wazuh/pull/7050))
  - Fixed a condition race hazard in Authd that may prevent the daemon from updating client.keys after adding an agent. ([#7271](https://github.com/wazuh/wazuh/pull/7271))
- **API:**
  - Fixed an error with `/groups/{group_id}/config` endpoints (GET and PUT) when using complex `localfile` configurations. ([#6276](https://github.com/wazuh/wazuh/pull/6383))
- **Framework:**
  - Fixed a `cluster_control` bug that caused an error message when running `wazuh-clusterd` in foreground. ([#6724](https://github.com/wazuh/wazuh/pull/6724))
  - Fixed a bug with add_manual(agents) function when authd is disabled. ([#7062](https://github.com/wazuh/wazuh/pull/7062))


## [v4.0.4] - 2021-01-14

### Added

- **API:**
  - Added missing secure headers for API responses. ([#7138](https://github.com/wazuh/wazuh/issues/7138))
  - Added new config option to disable uploading configurations containing remote commands. ([#7134](https://github.com/wazuh/wazuh/issues/7134))
  - Added new config option to choose the SSL ciphers. Default value `TLSv1.2`. ([#7164](https://github.com/wazuh/wazuh/issues/7164))

### Changed

- **API:**
  - Deprecated endpoints to restore and update API configuration file. ([#7132](https://github.com/wazuh/wazuh/issues/7132))
  - Default expiration time of the JWT token set to 15 minutes. ([#7167](https://github.com/wazuh/wazuh/pull/7167))

### Fixed

- **API:**
  - Fixed a path traversal flaw ([CVE-2021-26814](https://nvd.nist.gov/vuln/detail/CVE-2021-26814)) affecting 4.0.0 to 4.0.3 at `/manager/files` and `/cluster/{node_id}/files` endpoints. ([#7131](https://github.com/wazuh/wazuh/issues/7131))
- **Framework:**
  - Fixed a bug with add_manual(agents) function when authd is disabled. ([#7135](https://github.com/wazuh/wazuh/issues/7135))
- **Core:**
  - Fixed the purge of the Redhat vulnerabilities database before updating it. ([#7133](https://github.com/wazuh/wazuh/pull/7133))

## [v4.0.3] - 2020-11-30

### Fixed

- **API:**
  - Fixed a problem with certain API calls exceeding timeout in highly loaded cluster environments. ([#6753](https://github.com/wazuh/wazuh/pull/6753))


## [v4.0.2] - 2020-11-24

### Added

- **Core:**
  - Added macOS Big Sur version detection in the agent. ([#6603](https://github.com/wazuh/wazuh/pull/6603))

### Changed

- **API:**
  - `GET /agents/summary/os`, `GET /agents/summary/status` and `GET /overview/agents` will no longer consider `000` as an agent. ([#6574](https://github.com/wazuh/wazuh/pull/6574))
  - Increased to 64 the maximum number of characters that can be used in security users, roles, rules, and policies names. ([#6657](https://github.com/wazuh/wazuh/issues/6657))

### Fixed

- **API:**
  - Fixed an error with `POST /security/roles/{role_id}/rules` when removing role-rule relationships with admin resources. ([#6594](https://github.com/wazuh/wazuh/issues/6594))
  - Fixed a timeout error with `GET /manager/configuration/validation` when using it in a slow environment. ([#6530](https://github.com/wazuh/wazuh/issues/6530))
- **Framework:**
  - Fixed an error with some distributed requests when the cluster configuration is empty. ([#6612](https://github.com/wazuh/wazuh/pull/6612))
  - Fixed special characters in default policies. ([#6575](https://github.com/wazuh/wazuh/pull/6575))
- **Core:**
  - Fixed a bug in Remoted that limited the maximum agent number to `MAX_AGENTS-3` instead of `MAX_AGENTS-2`. ([#4560](https://github.com/wazuh/wazuh/pull/4560))
  - Fixed an error in the network library when handling disconnected sockets. ([#6444](https://github.com/wazuh/wazuh/pull/6444))
  - Fixed an error in FIM when handling temporary files and registry keys exceeding the path size limit. ([#6538](https://github.com/wazuh/wazuh/pull/6538))
  - Fixed a bug in FIM that stopped monitoring folders pointed by a symbolic link. ([#6613](https://github.com/wazuh/wazuh/pull/6613))
  - Fixed a race condition in FIM that could cause Syscheckd to stop unexpectedly. ([#6696](https://github.com/wazuh/wazuh/pull/6696))


## [v4.0.1] - 2020-11-11

### Changed

- **Framework:**
  - Updated Python's cryptography library to version 3.2.1 ([#6442](https://github.com/wazuh/wazuh/issues/6442))

### Fixed

- **API:**
  - Added missing agent:group resource to RBAC's catalog. ([6427](https://github.com/wazuh/wazuh/issues/6427))
  - Changed `limit` parameter behaviour in `GET sca/{agent_id}/checks/{policy_id}` endpoint and fixed some loss of information when paginating `wdb`. ([#6464](https://github.com/wazuh/wazuh/pull/6464))
  - Fixed an error with `GET /security/users/me` when logged in with `run_as`. ([#6506](https://github.com/wazuh/wazuh/pull/6506))
- **Framework:**
  - Fixed zip files compression and handling in cluster integrity synchronization. ([#6367](https://github.com/wazuh/wazuh/issues/6367))
- **Core**
  - Fixed version matching when assigning feed in Vulnerability Detector. ([#6505](https://github.com/wazuh/wazuh/pull/6505))
  - Prevent unprivileged users from accessing the Wazuh Agent folder in Windows. ([#3593](https://github.com/wazuh/wazuh/pull/3593))
  - Fix a bug that may lead the agent to crash when reading an invalid Logcollector configuration. ([#6463](https://github.com/wazuh/wazuh/pull/6463))


## [v4.0.0] - 2020-10-23

### Added

- Added **enrollment capability**. Agents are now able to request a key from the manager if current key is missing or wrong. ([#5609](https://github.com/wazuh/wazuh/pull/5609))
- Migrated the agent-info data to Wazuh DB. ([#5541](https://github.com/wazuh/wazuh/pull/5541))
- **API:**
  - Embedded Wazuh API with Wazuh Manager, there is no need to install Wazuh API. ([9860823](https://github.com/wazuh/wazuh/commit/9860823d568f5e6d93550d9b139507c04d2c2eb9))
  - Migrated Wazuh API server from nodejs to python. ([#2640](https://github.com/wazuh/wazuh/pull/2640))
  - Added asynchronous aiohttp server for the Wazuh API. ([#4474](https://github.com/wazuh/wazuh/issues/4474))
  - New Wazuh API is approximately 5 times faster on average. ([#5834](https://github.com/wazuh/wazuh/issues/5834))
  - Added OpenAPI based Wazuh API specification. ([#2413](https://github.com/wazuh/wazuh/issues/2413))
  - Improved Wazuh API reference documentation based on OpenAPI spec using redoc. ([#4967](https://github.com/wazuh/wazuh/issues/4967))
  - Added new yaml Wazuh API configuration file. ([#2570](https://github.com/wazuh/wazuh/issues/2570))
  - Added new endpoints to manage API configuration and deprecated configure_api.sh. ([#2570](https://github.com/wazuh/wazuh/issues/4822))
  - Added RBAC support to Wazuh API. ([#3287](https://github.com/wazuh/wazuh/issues/3287))
  - Added new endpoints for Wazuh API security management. ([#3410](https://github.com/wazuh/wazuh/issues/3410))
  - Added SQLAlchemy ORM based database for RBAC. ([#3375](https://github.com/wazuh/wazuh/issues/3375))
  - Added new JWT authentication method. ([7080ac3](https://github.com/wazuh/wazuh/commit/7080ac352774bb0feaf07cab76df58ea5503ff4b))
  - Wazuh API up and running by default in all nodes for a clustered environment.
  - Added new and improved error handling. ([#2843](https://github.com/wazuh/wazuh/issues/2843) ([#5345](https://github.com/wazuh/wazuh/issues/5345))
  - Added tavern and docker based Wazuh API integration tests. ([#3612](https://github.com/wazuh/wazuh/issues/3612))
  - Added new and unified Wazuh API responses structure. ([3421015](https://github.com/wazuh/wazuh/commit/34210154016f0a63211a81707744dce0ec0a54f9))
  - Added new endpoints for Wazuh API users management. ([#3280](https://github.com/wazuh/wazuh/issues/3280))
  - Added new endpoint to restart agents which belong to a node. ([#5381](https://github.com/wazuh/wazuh/issues/5381))
  - Added and improved q filter in several endpoints. ([#5431](https://github.com/wazuh/wazuh/pull/5431))
  - Tested and improved Wazuh API security. ([#5318](https://github.com/wazuh/wazuh/issues/5318))
    - Added DDOS blocking system. ([#5318](https://github.com/wazuh/wazuh/issues/5318#issuecomment-654303933))
    - Added brute force attack blocking system. ([#5318](https://github.com/wazuh/wazuh/issues/5318#issuecomment-652892858))
    - Added content-type validation. ([#5318](https://github.com/wazuh/wazuh/issues/5318#issuecomment-654807980))
- **Vulnerability Detector:**
  - Redhat vulnerabilities are now fetched from OVAL benchmarks. ([#5352](https://github.com/wazuh/wazuh/pull/5352))
  - Debian vulnerable packages are now fetched from the Security Tracker. ([#5304](https://github.com/wazuh/wazuh/pull/5304))
  - The Debian Security Tracker feed can be loaded from a custom location. ([#5449](https://github.com/wazuh/wazuh/pull/5449))
  - The package vendor is used to discard vulnerabilities. ([#5330](https://github.com/wazuh/wazuh/pull/5330))
  - Allow compressed feeds for offline updates. ([#5745](https://github.com/wazuh/wazuh/pull/5745))
  - The manager now updates the MSU feed automatically. ([#5678](https://github.com/wazuh/wazuh/pull/5678))
  - CVEs with no affected version defined in all the feeds are now reported. ([#5284](https://github.com/wazuh/wazuh/pull/5284))
  - CVEs vulnerable for the vendor and missing in the NVD are now reported. ([#5305](https://github.com/wazuh/wazuh/pull/5305))
- **File Integrity Monitoring:**
  - Added options to limit disk usage using report changes option in the FIM module. ([#5157](https://github.com/wazuh/wazuh/pull/5157))
- Added and updated framework unit tests to increase coverage. ([#3287](https://github.com/wazuh/wazuh/issues/3287))
- Added improved support for monitoring paths from environment variables. ([#4961](https://github.com/wazuh/wazuh/pull/4961))
- Added `base64_log` format to the log builder for Logcollector. ([#5273](https://github.com/wazuh/wazuh/pull/5273))

### Changed

- Changed the default manager-agent connection protocol to **TCP**. ([#5696](https://github.com/wazuh/wazuh/pull/5696))
- Disable perpetual connection attempts to modules. ([#5622](https://github.com/wazuh/wazuh/pull/5622))
- Unified the behaviour of Wazuh daemons when reconnecting with unix sockets. ([#4510](https://github.com/wazuh/wazuh/pull/4510))
- Changed multiple Wazuh API endpoints. ([#2640](https://github.com/wazuh/wazuh/pull/2640)) ([#2413](https://github.com/wazuh/wazuh-documentation/issues/2413))
- Refactored framework module in SDK and core. ([#5263](https://github.com/wazuh/wazuh/issues/5263))
- Refactored FIM Windows events handling. ([#5144](https://github.com/wazuh/wazuh/pull/5144))
- Changed framework to access global.db using wazuh-db. ([#6095](https://github.com/wazuh/wazuh/pull/6095))
- Changed agent-info synchronization task in Wazuh cluster. ([#5585](https://github.com/wazuh/wazuh/issues/5585))
- Use the proper algorithm name for SHA-256 inside Prelude output. Thanks to François Poirotte (@fpoirotte). ([#5004](https://github.com/wazuh/wazuh/pull/5004))
- Elastic Stack configuration files have been adapted to Wazuh v4.x. ([#5796](https://github.com/wazuh/wazuh/pull/5796))
- Explicitly use Bash for the Pagerduty integration. Thanks to Chris Kruger (@montdidier). ([#4641](https://github.com/wazuh/wazuh/pull/4641))

### Fixed

- **Vulnerability Detector:**
  - Vulnerabilities of Windows Server 2019 which not affects to Windows 10 were not being reported. ([#5524](https://github.com/wazuh/wazuh/pull/5524))
  - Vulnerabilities patched by a Microsoft update with no supersedence were not being reported. ([#5524](https://github.com/wazuh/wazuh/pull/5524))
  - Vulnerabilities patched by more than one Microsoft update were not being evaluated agains all the patches. ([#5717](https://github.com/wazuh/wazuh/pull/5717))
  - Duplicated alerts in Windows 10. ([#5600](https://github.com/wazuh/wazuh/pull/5600))
  - Syscollector now discards hotfixes that are not fully installed. ([#5792](https://github.com/wazuh/wazuh/pull/5792))
  - Syscollector now collects hotfixes that were not being parsed. ([#5792](https://github.com/wazuh/wazuh/pull/5792))
  - Update Windows databases when `run_on_start` is disabled. ([#5335](https://github.com/wazuh/wazuh/pull/5335))
  - Fixed the NVD version comparator to remove undesired suffixes. ([#5362](https://github.com/wazuh/wazuh/pull/5362))
  - Fixed not escaped single quote in vuln detector SQL query. ([#5570](https://github.com/wazuh/wazuh/pull/5570))
  - Unified alerts title. ([#5826](https://github.com/wazuh/wazuh/pull/5826))
  - Fixed potential error in the GZlib when uncompressing NVD feeds. ([#5989](https://github.com/wazuh/wazuh/pull/5989))
- **File Integrity Monitoring:**
  - Fixed an error with last scan time in Syscheck API endpoints. ([a9acd3a](https://github.com/wazuh/wazuh/commit/a9acd3a216a7e0075a8efa5a91b2587659782fd8))
  - Fixed support for monitoring directories which contain commas. ([#4961](https://github.com/wazuh/wazuh/pull/4961))
  - Fixed a bug where configuring a directory to be monitored as real-time and whodata resulted in real-time prevailing. ([#4961](https://github.com/wazuh/wazuh/pull/4961))
  - Fixed using an incorrect mutex while deleting inotify watches. ([#5126](https://github.com/wazuh/wazuh/pull/5126))
  - Fixed a bug which could cause multiple FIM threads to request the same temporary file. ([#5213](https://github.com/wazuh/wazuh/issues/5213))
  - Fixed a bug where deleting a file permanently in Windows would not trigger an alert. ([#5144](https://github.com/wazuh/wazuh/pull/5144))
  - Fixed a typo in the file monitoring options log entry. ([#5591](https://github.com/wazuh/wazuh/pull/5591))
  - Fixed an error where monitoring a drive in Windows under scheduled or realtime mode would generate alerts from the recycle bin. ([#4771](https://github.com/wazuh/wazuh/pull/4771))
  - When monitoring a drive in Windows in the format `U:`, it will monitor `U:\` instead of the agent's working directory. ([#5259](https://github.com/wazuh/wazuh/pull/5259))
  - Fixed a bug where monitoring a drive in Windows with `recursion_level` set to 0 would trigger alerts from files inside its subdirectories. ([#5235](https://github.com/wazuh/wazuh/pull/5235))
- Fixed an Azure wodle dependency error. The package azure-storage-blob>12.0.0 does not include a component used. ([#6109](https://github.com/wazuh/wazuh/pull/6109))
- Fixed bugs reported by GCC 10.1.0. ([#5119](https://github.com/wazuh/wazuh/pull/5119))
- Fixed compilation errors with `USE_PRELUDE` enabled. Thanks to François Poirotte (@fpoirotte). ([#5003](https://github.com/wazuh/wazuh/pull/5003))
- Fixed default gateway data gathering in Syscollector on Linux 2.6. ([#5548](https://github.com/wazuh/wazuh/pull/5548))
- Fixed the Eventchannel collector to keep working when the Eventlog service is restarted. ([#5496](https://github.com/wazuh/wazuh/pull/5496))
- Fixed the OpenSCAP script to work over Python 3. ([#5317](https://github.com/wazuh/wazuh/pull/5317))
- Fixed the launcher.sh generation in macOS source installation. ([#5922](https://github.com/wazuh/wazuh/pull/5922))

### Removed

- Removed Wazuh API cache endpoints. ([#3042](https://github.com/wazuh/wazuh/pull/3042))
- Removed Wazuh API rootcheck endpoints. ([#5246](https://github.com/wazuh/wazuh/issues/5246))
- Deprecated Debian Jessie and Wheezy for Vulnerability Detector (EOL). ([#5660](https://github.com/wazuh/wazuh/pull/5660))
- Removed references to `manage_agents` in the installation process. ([#5840](https://github.com/wazuh/wazuh/pull/5840))
- Removed compatibility with deprecated configuration at Vulnerability Detector. ([#5879](https://github.com/wazuh/wazuh/pull/5879))


## [v3.13.6] - 2022-09-19

### Fixed

- Fixed a path traversal flaw in Active Response affecting agents from v3.6.1 (reported by @guragainroshan0). ([#14823](https://github.com/wazuh/wazuh/pull/14823))


## [v3.13.4] - 2022-05-30

### Fixed

- Fixed a crash in Vuln Detector when scanning agents running on Windows (backport from 4.3.2). ([#13624](https://github.com/wazuh/wazuh/pull/13624))


## [v3.13.3] - 2021-04-28

### Fixed

- Fixed a bug in Vulnerability Detector that made Modulesd crash while updating the NVD feed due to a missing CPE entry. ([#8346](https://github.com/wazuh/wazuh/pull/8346))


## [v3.13.2] - 2020-09-21

### Fixed

- Updated the default NVD feed URL from 1.0 to 1.1 in Vulnerability Detector. ([#6056](https://github.com/wazuh/wazuh/pull/6056))


## [v3.13.1] - 2020-07-14

### Added

- Added two new settings <max_retries> and <retry_interval> to adjust the agent failover interval. ([#5433](https://github.com/wazuh/wazuh/pull/5433))

### Fixed

- Fixed a crash in Modulesd caused by Vulnerability Detector when skipping a kernel package if the agent has OS info disabled. ([#5467](https://github.com/wazuh/wazuh/pull/5467))


## [v3.13.0] - 2020-06-29

### Added

- Vulnerability Detector improvements. ([#5097](https://github.com/wazuh/wazuh/pull/5097))
  - Include the NVD as feed for Linux agents in Vulnerability Detector.
  - Improve the Vulnerability Detector engine to correlate alerts between different feeds.
  - Add Vulnerability Detector module unit testing for Unix source code.
  - A timeout has been added to the updates of the vulnerability detector feeds to prevent them from getting hung up. ([#5153](https://github.com/wazuh/wazuh/pull/5153))
- New option for the JSON decoder to choose the treatment of Array structures. ([#4836](https://github.com/wazuh/wazuh/pull/4836))
- Added mode value (real-time, Who-data, or scheduled) as a dynamic field in FIM alerts. ([#5051](https://github.com/wazuh/wazuh/pull/5051))
- Set a configurable maximum limit of files to be monitored by FIM. ([#4717](https://github.com/wazuh/wazuh/pull/4717))
- New integration for pull logs from Google Cloud Pub/Sub. ([#4078](https://github.com/wazuh/wazuh/pull/4078))
- Added support for MITRE ATT&CK knowledge base. ([#3746](https://github.com/wazuh/wazuh/pull/3746))
- Microsoft Software Update Catalog used by vulnerability detector added as a dependency. ([#5101](https://github.com/wazuh/wazuh/pull/5101))
- Added support for `aarch64` and `armhf` architectures. ([#5030](https://github.com/wazuh/wazuh/pull/5030))

### Changed

- Internal variable rt_delay configuration changes to 5 milliseconds. ([#4760](https://github.com/wazuh/wazuh/pull/4760))
- Who-data includes new fields: process CWD, parent process id, and CWD of parent process. ([#4782](https://github.com/wazuh/wazuh/pull/4782))
- FIM opens files with shared deletion permission. ([#5018](https://github.com/wazuh/wazuh/pull/5018))
- Extended the statics fields comparison in the ruleset options. ([#4416](https://github.com/wazuh/wazuh/pull/4416))
- The state field was removed from vulnerability alerts. ([#5211](https://github.com/wazuh/wazuh/pull/5211))
- The NVD is now the primary feed for the vulnerability detector in Linux. ([#5097](https://github.com/wazuh/wazuh/pull/5097))
- Removed OpenSCAP policies installation and configuration block. ([#5061](https://github.com/wazuh/wazuh/pull/5061))
- Changed the internal configuration of Analysisd to be able to register by default a number of agents higher than 65536. ([#4332](https://github.com/wazuh/wazuh/pull/4332))
- Changed `same/different_systemname` for `same/different_system_name` in Analysisd static filters. ([#5131](https://github.com/wazuh/wazuh/pull/5131))
- Updated the internal Python interpreter from v3.7.2 to v3.8.2. ([#5030](https://github.com/wazuh/wazuh/pull/5030))

### Fixed

- Fixed a bug that, in some cases, kept the memory reserved when deleting monitored directories in FIM. ([#5115](https://github.com/wazuh/wazuh/issues/5115))
- Freed Inotify watches moving directories in the real-time mode of FIM. ([#4794](https://github.com/wazuh/wazuh/pull/4794))
- Fixed an error that caused deletion alerts with a wrong path in Who-data mode. ([#4831](https://github.com/wazuh/wazuh/pull/4831))
- Fixed generating alerts in Who-data mode when moving directories to the folder being monitored in Windows. ([#4762](https://github.com/wazuh/wazuh/pull/4762))
- Avoid truncating the full log field of the alert when the path is too long. ([#4792](https://github.com/wazuh/wazuh/pull/4792))
- Fixed the change of monitoring from Who-data to real-time when there is a failure to set policies in Windows. ([#4753](https://github.com/wazuh/wazuh/pull/4753))
- Fixed an error that prevents restarting Windows agents from the manager. ([#5212](https://github.com/wazuh/wazuh/pull/5212))
- Fixed an error that impedes the use of the tag URL by configuring the NVD in a vulnerability detector module. ([#5165](https://github.com/wazuh/wazuh/pull/5165))
- Fixed TOCTOU condition in Clusterd when merging agent-info files. ([#5159](https://github.com/wazuh/wazuh/pull/5159))
- Fixed race condition in Analysisd when handling accumulated events. ([#5091](https://github.com/wazuh/wazuh/pull/5091))
- Avoided to count links when generating alerts for ignored directories in Rootcheck. Thanks to Artur Molchanov (@Hexta). ([#4603](https://github.com/wazuh/wazuh/pull/4603))
- Fixed typo in the path used for logging when disabling an account. Thanks to Fontaine Pierre (@PierreFontaine). ([#4839](https://github.com/wazuh/wazuh/pull/4839))
- Fixed an error when receiving different Syslog events in the same TCP packet. ([#5087](https://github.com/wazuh/wazuh/pull/5087))
- Fixed a bug in Vulnerability Detector on Modulesd when comparing Windows software versions. ([#5168](https://github.com/wazuh/wazuh/pull/5168))
- Fixed a bug that caused an agent's disconnection time not to be displayed correctly. ([#5142](https://github.com/wazuh/wazuh/pull/5142))
- Optimized the function to obtain the default gateway. Thanks to @WojRep
- Fixed host verification when signing a certificate for the manager. ([#4963](https://github.com/wazuh/wazuh/pull/4963))
- Fixed possible duplicated ID on 'client.keys' adding new agent through the API with a specific ID. ([#4982](https://github.com/wazuh/wazuh/pull/4982))
- Avoid duplicate descriptors using wildcards in 'localfile' configuration. ([#4977](https://github.com/wazuh/wazuh/pull/4977))
- Added guarantee that all processes are killed when service stops. ([#4975](https://github.com/wazuh/wazuh/pull/4975))
- Fixed mismatch in integration scripts when the debug flag is set to active. ([#4800](https://github.com/wazuh/wazuh/pull/4800))


## [v3.12.3] - 2020-04-30

### Changed

- Disable WAL in databases handled by Wazuh DB to save disk space. ([#4949](https://github.com/wazuh/wazuh/pull/4949))

### Fixed

- Fixed a bug in Remoted that could prevent agents from connecting in UDP mode. ([#4897](https://github.com/wazuh/wazuh/pull/4897))
- Fixed a bug in the shared library that caused daemons to not find the ossec group. ([#4873](https://github.com/wazuh/wazuh/pull/4873))
- Prevent Syscollector from falling into an infinite loop when failed to collect the Windows hotfixes. ([#4878](https://github.com/wazuh/wazuh/pull/4878))
- Fixed a memory leak in the system scan by Rootcheck on Windows. ([#4948](https://github.com/wazuh/wazuh/pull/4948))
- Fixed a bug in Logcollector that caused the out_format option not to apply for the agent target. ([#4942](https://github.com/wazuh/wazuh/pull/4942))
- Fixed a bug that caused FIM to not handle large inode numbers correctly. ([#4914](https://github.com/wazuh/wazuh/pull/4914))
- Fixed a bug that made ossec-dbd crash due to a bad mutex initialization. ([#4552](https://github.com/wazuh/wazuh/pull/4552))


## [v3.12.2] - 2020-04-09

### Fixed

- Fixed a bug in Vulnerability Detector that made wazuh-modulesd crash when parsing the version of a package from a RHEL feed. ([#4885](https://github.com/wazuh/wazuh/pull/4885))


## [v3.12.1] - 2020-04-08

### Changed

- Updated MSU catalog on 31/03/2020. ([#4819](https://github.com/wazuh/wazuh/pull/4819))

### Fixed

- Fixed compatibility with the Vulnerability Detector feeds for Ubuntu from Canonical, that are available in a compressed format. ([#4834](https://github.com/wazuh/wazuh/pull/4834))
- Added missing field ‘database’ to the FIM on-demand configuration report. ([#4785](https://github.com/wazuh/wazuh/pull/4785))
- Fixed a bug in Logcollector that made it forward a log to an external socket infinite times. ([#4802](https://github.com/wazuh/wazuh/pull/4802))
- Fixed a buffer overflow when receiving large messages from Syslog over TCP connections. ([#4778](https://github.com/wazuh/wazuh/pull/4778))
- Fixed a malfunction in the Integrator module when analyzing events without a certain field. ([#4851](https://github.com/wazuh/wazuh/pull/4851))
- Fix XML validation with paths ending in `\`. ([#4783](https://github.com/wazuh/wazuh/pull/4783))

### Removed

- Removed support for Ubuntu 12.04 (Precise) in Vulneratiliby Detector as its feed is no longer available.


## [v3.12.0] - 2020-03-24

### Added

- Add synchronization capabilities for FIM. ([#3319](https://github.com/wazuh/wazuh/issues/3319))
- Add SQL database for the FIM module. Its storage can be switched between disk and memory. ([#3319](https://github.com/wazuh/wazuh/issues/3319))
- Add support for monitoring AWS S3 buckets in GovCloud regions. ([#3953](https://github.com/wazuh/wazuh/issues/3953))
- Add support for monitoring Cisco Umbrella S3 buckets. ([#3890](https://github.com/wazuh/wazuh/issues/3890))
- Add automatic reconnection with the Eventchannel service when it is restarted. ([#3836](https://github.com/wazuh/wazuh/pull/3836))
- Add a status validation when starting Wazuh. ([#4237](https://github.com/wazuh/wazuh/pull/4237))
- Add FIM module unit testing for Unix source code. ([#4688](https://github.com/wazuh/wazuh/pull/4688))
- Add multi-target support for unit testing. ([#4564](https://github.com/wazuh/wazuh/pull/4564))
- Add FIM module unit testing for Windows source code. ([#4633](https://github.com/wazuh/wazuh/pull/4633))

### Changed

- Move the FIM logic engine to the agent. ([#3319](https://github.com/wazuh/wazuh/issues/3319))
- Make Logcollector continuously attempt to reconnect with the agent daemon. ([#4435](https://github.com/wazuh/wazuh/pull/4435))
- Make Windows agents to send the keep-alive independently. ([#4077](https://github.com/wazuh/wazuh/pull/4077))
- Do not enforce source IP checking by default in the registration process. ([#4083](https://github.com/wazuh/wazuh/pull/4083))
- Updated API manager/configuration endpoint to also return the new synchronization and whodata syscheck fields ([#4241](https://github.com/wazuh/wazuh/pull/4241))
- Disabled the chroot jail in Agentd on UNIX.

### Fixed

- Avoid reopening the current socket when Logcollector fails to send a event. ([#4696](https://github.com/wazuh/wazuh/pull/4696))
- Prevent Logcollector from starving when has to reload files. ([#4730](https://github.com/wazuh/wazuh/pull/4730))
- Fix a small memory leak in clusterd. ([#4465](https://github.com/wazuh/wazuh/pull/4465))
- Fix a crash in the fluent forwarder when SSL is not enabled. ([#4675](https://github.com/wazuh/wazuh/pull/4675))
- Replace non-reentrant functions to avoid race condition hazards. ([#4081](https://github.com/wazuh/wazuh/pull/4081))
- Fixed the registration of more than one agent as `any` when forcing to use the source IP. ([#2533](https://github.com/wazuh/wazuh/pull/2533))
- Fix Windows upgrades in custom directories. ([#2534](https://github.com/wazuh/wazuh/pull/2534))
- Fix the format of the alert payload passed to the Slack integration. ([#3978](https://github.com/wazuh/wazuh/pull/3978))


## [v3.11.4] - 2020-02-25

### Changed

- Remove chroot in Agentd to allow it resolve DNS at any time. ([#4652](https://github.com/wazuh/wazuh/issues/4652))


## [v3.11.3] - 2020-01-28

### Fixed

- Fixed a bug in the Windows agent that made Rootcheck report false positives about file size mismatch. ([#4493](https://github.com/wazuh/wazuh/pull/4493))


## [v3.11.2] - 2020-01-22

### Changed

- Optimized memory usage in Vulnerability Detector when fetching the NVD feed. ([#4427](https://github.com/wazuh/wazuh/pull/4427))

### Fixed

- Rootcheck scan produced a 100% CPU peak in Syscheckd because it applied `<readall>` option even when disabled. ([#4415](https://github.com/wazuh/wazuh/pull/4415))
- Fixed a handler leak in Rootcheck and SCA on Windows agents. ([#4456](https://github.com/wazuh/wazuh/pull/4456))
- Prevent Remoted from exiting when a client closes a connection prematurely. ([#4390](https://github.com/wazuh/wazuh/pull/4390))
- Fixed crash in Slack integration when handling an alert with no description. ([#4426](https://github.com/wazuh/wazuh/pull/4426))
- Fixed Makefile to allow running scan-build for Windows agents. ([#4314](https://github.com/wazuh/wazuh/pull/4314))
- Fixed a memory leak in Clusterd. ([#4448](https://github.com/wazuh/wazuh/pull/4448))
- Disable TCP keepalive options at os_net library to allow building Wazuh on OpenBSD. ([#4462](https://github.com/wazuh/wazuh/pull/4462))


## [v3.11.1] - 2020-01-03

### Fixed

- The Windows Eventchannel log decoder in Analysisd maxed out CPU usage due to an infinite loop. ([#4412](https://github.com/wazuh/wazuh/pull/4412))


## [v3.11.0] - 2019-12-23

### Added

- Add support to Windows agents for vulnerability detector. ([#2787](https://github.com/wazuh/wazuh/pull/2787))
- Add support to Debian 10 Buster for vulnerability detector (by @aderumier). ([#4151](https://github.com/wazuh/wazuh/pull/4151))
- Make the Wazuh service to start after the network systemd unit (by @VAdamec). ([#1106](https://github.com/wazuh/wazuh/pull/1106))
- Add process inventory support for Mac OS X agents. ([#3322](https://github.com/wazuh/wazuh/pull/3322))
- Add port inventory support for MAC OS X agents. ([#3349](https://github.com/wazuh/wazuh/pull/3349))
- Make Analysisd compile the CDB list upon start. ([#3488](https://github.com/wazuh/wazuh/pull/3488))
- New rules option `global_frequency` to make frequency rules independent from the event source. ([#3931](https://github.com/wazuh/wazuh/pull/3931))
- Add a validation for avoiding agents to keep trying to connect to an invalid address indefinitely. ([#3951](https://github.com/wazuh/wazuh/pull/3951))
- Add the condition field of SCA checks to the agent databases. ([#3631](https://github.com/wazuh/wazuh/pull/3631))
- Display a warning message when registering to an unverified manager. ([#4207](https://github.com/wazuh/wazuh/pull/4207))
- Allow JSON escaping for logs on Logcollector's output format. ([#4273](https://github.com/wazuh/wazuh/pull/4273))
- Add TCP keepalive support for Fluent Forwarder. ([#4274](https://github.com/wazuh/wazuh/pull/4274))
- Add the host's primary IP to Logcollector's output format. ([#4380](https://github.com/wazuh/wazuh/pull/4380))

### Changed

- Now EventChannel alerts include the full message with the translation of coded fields. ([#3320](https://github.com/wazuh/wazuh/pull/3320))
- Changed `-G` agent-auth description in help message. ([#3856](https://github.com/wazuh/wazuh/pull/3856))
- Unified the Makefile flags allowed values. ([#4034](https://github.com/wazuh/wazuh/pull/4034))
- Let Logcollector queue file rotation and keepalive messages. ([#4222](https://github.com/wazuh/wazuh/pull/4222))
- Changed default paths for the OSQuery module in Windows agents. ([#4148](https://github.com/wazuh/wazuh/pull/4148))
- Fluent Forward now packs the content towards Fluentd into an object. ([#4334](https://github.com/wazuh/wazuh/pull/4334))

### Fixed

- Fix frequency rules to be increased for the same agent by default. ([#3931](https://github.com/wazuh/wazuh/pull/3931))
- Fix `protocol`, `system_name`, `data` and `extra_data` static fields detection. ([#3591](https://github.com/wazuh/wazuh/pull/3591))
- Fix overwriting agents by `Authd` when `force` option is less than 0. ([#3527](https://github.com/wazuh/wazuh/pull/3527))
- Fix Syscheck `nodiff` option for substring paths. ([#3015](https://github.com/wazuh/wazuh/pull/3015))
- Fix Logcollector wildcards to not detect directories as log files. ([#3788](https://github.com/wazuh/wazuh/pull/3788))
- Make Slack integration work with agentless alerts (by @dmitryax). ([#3971](https://github.com/wazuh/wazuh/pull/3971))
- Fix bugs reported by Clang analyzer. ([#3887](https://github.com/wazuh/wazuh/pull/3887))
- Fix compilation errors on OpenBSD platform. ([#3105](https://github.com/wazuh/wazuh/pull/3105))
- Fix on-demand configuration labels section to obtain labels attributes. ([#3490](https://github.com/wazuh/wazuh/pull/3490))
- Fixed race condition between `wazuh-clusterd` and `wazuh-modulesd` showing a 'No such file or directory' in `cluster.log` when synchronizing agent-info files in a cluster environment ([#4007](https://github.com/wazuh/wazuh/issues/4007))
- Fixed 'ConnectionError object has no attribute code' error when package repository is not available ([#3441](https://github.com/wazuh/wazuh/issues/3441))
- Fix the blocking of files monitored by Who-data in Windows agents. ([#3872](https://github.com/wazuh/wazuh/pull/3872))
- Fix the processing of EventChannel logs with unexpected characters. ([#3320](https://github.com/wazuh/wazuh/pull/3320))
- Active response Kaspersky script now logs the action request in _active-responses.log_ ([#2748](https://github.com/wazuh/wazuh/pull/2748))
- Fix service's installation path for CentOS 8. ([#4060](https://github.com/wazuh/wazuh/pull/4060))
- Add macOS Catalina to the list of detected versions. ([#4061](https://github.com/wazuh/wazuh/pull/4061))
- Prevent FIM from producing false negatives due to wrong checksum comparison. ([#4066](https://github.com/wazuh/wazuh/pull/4066))
- Fix `previous_output` count for alerts when matching by group. ([#4097](https://github.com/wazuh/wazuh/pull/4097))
- Fix event iteration when evaluating contextual rules. ([#4106](https://github.com/wazuh/wazuh/pull/4106))
- Fix the use of `prefilter_cmd` remotely by a new local option `allow_remote_prefilter_cmd`. ([#4178](https://github.com/wazuh/wazuh/pull/4178) & [4194](https://github.com/wazuh/wazuh/pull/4194))
- Fix restarting agents by group using the API when some of them are in a worker node. ([#4226](https://github.com/wazuh/wazuh/pull/4226))
- Fix error in Fluent Forwarder that requests an user and pass although the server does not need it. ([#3910](https://github.com/wazuh/wazuh/pull/3910))
- Fix FTS data length bound mishandling in Analysisd. ([#4278](https://github.com/wazuh/wazuh/pull/4278))
- Fix a memory leak in Modulesd and Agentd when Fluent Forward parses duplicate options. ([#4334](https://github.com/wazuh/wazuh/pull/4334))
- Fix an invalid memory read in Agentd when checking a remote configuration containing an invalid stanza inside `<labels>`. ([#4334](https://github.com/wazuh/wazuh/pull/4334))
- Fix error using force_reload and the eventchannel format in UNIX systems. ([#4294](https://github.com/wazuh/wazuh/pull/4294))


## [v3.10.2] - 2019-09-23

### Fixed

- Fix error in Logcollector when reloading localfiles with timestamp wildcards. ([#3995](https://github.com/wazuh/wazuh/pull/3995))


## [v3.10.1] - 2019-09-19

### Fixed

- Fix error after removing a high volume of agents from a group using the Wazuh API. ([#3907](https://github.com/wazuh/wazuh/issues/3907))
- Fix error in Remoted when reloading agent keys (busy resource). ([#3988](https://github.com/wazuh/wazuh/issues/3988))
- Fix invalid read in Remoted counters. ([#3989](https://github.com/wazuh/wazuh/issues/3989))


## [v3.10.0] - 2019-09-16

### Added

- Add framework function to obtain full summary of agents. ([#3842](https://github.com/wazuh/wazuh/pull/3842))
- SCA improvements. ([#3286](https://github.com/wazuh/wazuh/pull/3286))
  - Refactor de SCA internal logic and policy syntax. ([#3249](https://github.com/wazuh/wazuh/issues/3249))
  - Support to follow symbolic links. ([#3228](https://github.com/wazuh/wazuh/issues/3228))
  - Add numerical comparator for SCA rules. ([#3374](https://github.com/wazuh/wazuh/issues/3374))
  - Add SCA decoded events count to global stats. ([#3623](https://github.com/wazuh/wazuh/issues/3623))
- Extend duplicate file detection for LogCollector. ([#3867](https://github.com/wazuh/wazuh/pull/3867))
- Add HIPAA and NIST 800 53 compliance mapping as rule groups.([#3411](https://github.com/wazuh/wazuh/pull/3411) & [#3420](https://github.com/wazuh/wazuh/pull/3420))
- Add SCA compliance groups to rule groups in alerts. ([#3427](https://github.com/wazuh/wazuh/pull/3427))
- Add IPv6 loopback address to localhost list in DB output module (by @aquerubin). ([#3140](https://github.com/wazuh/wazuh/pull/3140))
- Accept `]` and `>` as terminal prompt characters for Agentless. ([#3209](https://github.com/wazuh/wazuh/pull/3209))

### Changed

- Modify logs for agent authentication issues by Remoted. ([#3662](https://github.com/wazuh/wazuh/pull/3662))
- Make Syscollector logging messages more user-friendly. ([#3397](https://github.com/wazuh/wazuh/pull/3397))
- Make SCA load by default all present policies at the default location. ([#3607](https://github.com/wazuh/wazuh/pull/3607))
- Increase IPSIZE definition for IPv6 compatibility (by @aquerubin). ([#3259](https://github.com/wazuh/wazuh/pull/3259))
- Replace local protocol definitions with Socket API definitions (by @aquerubin). ([#3260](https://github.com/wazuh/wazuh/pull/3260))
- Improved error message when some of required Wazuh daemons are down. Allow restarting cluster nodes except when `ossec-execd` is down. ([#3496](https://github.com/wazuh/wazuh/pull/3496))
- Allow existing aws_profile argument to work with vpcflowlogs in AWS wodle configuration. Thanks to Adam Williams (@awill1988). ([#3729](https://github.com/wazuh/wazuh/pull/3729))

### Fixed

- Fix exception handling when using an invalid bucket in AWS wodle ([#3652](https://github.com/wazuh/wazuh/pull/3652))
- Fix error message when an AWS bucket is empty ([#3743](https://github.com/wazuh/wazuh/pull/3743))
- Fix error when getting profiles in custom AWS buckets ([#3786](https://github.com/wazuh/wazuh/pull/3786))
- Fix SCA integrity check when switching between manager nodes. ([#3884](https://github.com/wazuh/wazuh/pull/3884))
- Fix alert email sending when no_full_log option is set in a rule. ([#3174](https://github.com/wazuh/wazuh/pull/3174))
- Fix error in Windows who-data when handling the directories list. ([#3883](https://github.com/wazuh/wazuh/pull/3883))
- Fix error in the hardware inventory collector for PowerPC architectures. ([#3624](https://github.com/wazuh/wazuh/pull/3624))
- Fix the use of mutexes in the `OS_Regex` library. ([#3533](https://github.com/wazuh/wazuh/pull/3533))
- Fix invalid read in the `OS_Regex` library. ([#3815](https://github.com/wazuh/wazuh/pull/3815))
- Fix compilation error on FreeBSD 13 and macOS 10.14. ([#3832](https://github.com/wazuh/wazuh/pull/3832))
- Fix typo in the license of the files. ([#3779](https://github.com/wazuh/wazuh/pull/3779))
- Fix error in `execd` when upgrading agents remotely while auto-restarting. ([#3437](https://github.com/wazuh/wazuh/pull/3437))
- Prevent integrations from inheriting descriptors. ([#3514](https://github.com/wazuh/wazuh/pull/3514))
- Overwrite rules label fix and rules features tests. ([#3414](https://github.com/wazuh/wazuh/pull/3414))
- Fix typo: replace `readed` with `read`. ([#3328](https://github.com/wazuh/wazuh/pull/3328))
- Introduce global mutex for Rootcheck decoder. ([#3530](https://github.com/wazuh/wazuh/pull/3530))
- Fix errors reported by scan-build. ([#3452](https://github.com/wazuh/wazuh/pull/3452) & [#3785](https://github.com/wazuh/wazuh/pull/3785))
- Fix the handling of `wm_exec()` output.([#3486](https://github.com/wazuh/wazuh/pull/3486))
- Fix FIM duplicated entries in Windows. ([#3504](https://github.com/wazuh/wazuh/pull/3504))
- Remove socket deletion from epoll. ([#3432](https://github.com/wazuh/wazuh/pull/3432))
- Let the sources installer support NetBSD. ([#3444](https://github.com/wazuh/wazuh/pull/3444))
- Fix error message from openssl v1.1.1. ([#3413](https://github.com/wazuh/wazuh/pull/3413))
- Fix compilation issue for local installation. ([#3339](https://github.com/wazuh/wazuh/pull/3339))
- Fix exception handling when /tmp have no permissions and tell the user the problem. ([#3401](https://github.com/wazuh/wazuh/pull/3401))
- Fix who-data alerts when audit logs contain hex fields. ([#3909](https://github.com/wazuh/wazuh/pull/3909))
- Remove useless `select()` calls in Analysisd decoders. ([#3964](https://github.com/wazuh/wazuh/pull/3964))


## [v3.9.5] - 2019-08-08

### Fixed

- Fixed a bug in the Framework that prevented Cluster and API from handling the file _client.keys_ if it's mounted as a volume on Docker.
- Fixed a bug in Analysisd that printed the millisecond part of the alerts' timestamp without zero-padding. That prevented Elasticsearch 7 from indexing those alerts. ([#3814](https://github.com/wazuh/wazuh/issues/3814))


## [v3.9.4] - 2019-08-07

### Changed

- Prevent agent on Windows from including who-data on FIM events for child directories without who-data enabled, even if it's available. ([#3601](https://github.com/wazuh/wazuh/issues/3601))
- Prevent Rootcheck configuration from including the `<ignore>` settings if they are empty. ([#3634](https://github.com/wazuh/wazuh/issues/3634))
- Wazuh DB will delete the agent DB-related files immediately when removing an agent. ([#3691](https://github.com/wazuh/wazuh/issues/3691))

### Fixed

- Fixed bug in Remoted when correlating agents and their sockets in TCP mode. ([#3602](https://github.com/wazuh/wazuh/issues/3602))
- Fix bug in the agent that truncated its IP address if it occupies 15 characters. ([#3615](https://github.com/wazuh/wazuh/issues/3615))
- Logcollector failed to overwrite duplicate `<localfile>` stanzas. ([#3616](https://github.com/wazuh/wazuh/issues/3616))
- Analysisd could produce a double free if an Eventchannel message contains an invalid XML member. ([#3626](https://github.com/wazuh/wazuh/issues/3626))
- Fixed defects in the code reported by Coverity. ([#3627](https://github.com/wazuh/wazuh/issues/3627))
- Fixed bug in Analysisd when handling invalid JSON input strings. ([#3648](https://github.com/wazuh/wazuh/issues/3648))
- Fix handling of SCA policies with duplicate ID in Wazuh DB. ([#3668](https://github.com/wazuh/wazuh/issues/3668))
- Cluster could fail synchronizing some files located in Docker volumes. ([#3669](https://github.com/wazuh/wazuh/issues/3669))
- Fix a handler leak in the FIM whodata engine for Windows. ([#3690](https://github.com/wazuh/wazuh/issues/3690))
- The Docker listener module was storing and ignoring the output of the integration. ([#3768](https://github.com/wazuh/wazuh/issues/3768))
- Fixed memory leaks in Syscollector for macOS agents. ([#3795](https://github.com/wazuh/wazuh/pull/3795))
- Fix dangerous mutex initialization in Windows hosts. ([#3805](https://github.com/wazuh/wazuh/issues/3805))


## [v3.9.3] - 2019-07-08

### Changed

- Windows Eventchannel log collector will no longer report bookmarked events by default (those that happened while the agent was stopped). ([#3485](https://github.com/wazuh/wazuh/pull/3485))
- Remoted will discard agent-info data not in UTF-8 format. ([#3581](https://github.com/wazuh/wazuh/pull/3581))

### Fixed

- Osquery integration did not follow the osquery results file (*osqueryd.results.log*) as of libc 2.28. ([#3494](https://github.com/wazuh/wazuh/pull/3494))
- Windows Eventchannnel log collector did not update the bookmarks so it reported old events repeatedly. ([#3485](https://github.com/wazuh/wazuh/pull/3485))
- The agent sent invalid info data in the heartbeat message if it failed to get the host IP address. ([#3555](https://github.com/wazuh/wazuh/pull/3555))
- Modulesd produced a memory leak when being queried for its running configuration. ([#3564](https://github.com/wazuh/wazuh/pull/3564))
- Analysisd and Logtest crashed when trying rules having `<different_geoip>` and no `<not_same_field>` stanza. ([#3587](https://github.com/wazuh/wazuh/pull/3587))
- Vulnerability Detector failed to parse the Canonical's OVAL feed due to a syntax change. ([#3563](https://github.com/wazuh/wazuh/pull/3563))
- AWS Macie events produced erros in Elasticsearch. ([#3608](https://github.com/wazuh/wazuh/pull/3608))
- Rules with `<list lookup="address_match_key" />` produced a false match if the CDB list file is missing. ([#3609](https://github.com/wazuh/wazuh/pull/3609))
- Remote configuration was missing the `<ignore>` stanzas for Syscheck and Rootcheck when defined as sregex. ([#3617](https://github.com/wazuh/wazuh/pull/3617))


## [v3.9.2] - 2019-06-10

### Added

- Added support for Ubuntu 12.04 to the SCA configuration template. ([#3361](https://github.com/wazuh/wazuh/pull/3361))

### Changed

- Prevent the agent from stopping if it fails to resolve the manager's hostname on startup. ([#3405](https://github.com/wazuh/wazuh/pull/3405))
- Prevent Remoted from logging agent connection timeout as an error, now it's a debugging log. ([#3426](https://github.com/wazuh/wazuh/pull/3426))

### Fixed

- A configuration request to Analysisd made it crash if the option `<white_list>` is empty. ([#3383](https://github.com/wazuh/wazuh/pull/3383))
- Fixed error when uploading some configuration files through API in wazuh-docker environments. ([#3335](https://github.com/wazuh/wazuh/issues/3335))
- Fixed error deleting temporary files during cluster synchronization. ([#3379](https://github.com/wazuh/wazuh/issues/3379))
- Fixed bad permissions on agent-groups files synchronized via wazuh-clusterd. ([#3438](https://github.com/wazuh/wazuh/issues/3438))
- Fixed bug in the database module that ignored agents registered with a network mask. ([#3351](https://github.com/wazuh/wazuh/pull/3351))
- Fixed a memory bug in the CIS-CAT module. ([#3406](https://github.com/wazuh/wazuh/pull/3406))
- Fixed a bug in the agent upgrade tool when checking the version number. ([#3391](https://github.com/wazuh/wazuh/pull/3391))
- Fixed error checking in the Windows Eventchannel log collector. ([#3393](https://github.com/wazuh/wazuh/pull/3393))
- Prevent Analysisd from crashing at SCA decoder due to a race condition calling a thread-unsafe function. ([#3466](https://github.com/wazuh/wazuh/pull/3466))
- Fix a file descriptor leak in Modulesd on timeout when running a subprocess. ([#3470](https://github.com/wazuh/wazuh/pull/3470))
  - OpenSCAP.
  - CIS-CAT.
  - Command.
  - Azure.
  - SCA.
  - AWS.
  - Docker.
- Prevent Modulesd from crashing at Vulnerability Detector when updating a RedHat feed. ([3458](https://github.com/wazuh/wazuh/pull/3458))


## [v3.9.1] - 2019-05-21

### Added

- Added directory existence checking for SCA rules. ([#3246](https://github.com/wazuh/wazuh/pull/3246))
- Added line number to error messages when parsing YAML files. ([#3325](https://github.com/wazuh/wazuh/pull/3325))
- Enhanced wildcard support for Windows Logcollector. ([#3236](https://github.com/wazuh/wazuh/pull/3236))

### Changed

- Changed the extraction point of the package name in the Vulnerability Detector OVALs. ([#3245](https://github.com/wazuh/wazuh/pull/3245))

### Fixed

- Fixed SCA request interval option limit. ([#3254](https://github.com/wazuh/wazuh/pull/3254))
- Fixed SCA directory checking. ([#3235](https://github.com/wazuh/wazuh/pull/3235))
- Fixed potential out of bounds memory access. ([#3285](https://github.com/wazuh/wazuh/pull/3285))
- Fixed CIS-CAT XML report parser. ([#3261](https://github.com/wazuh/wazuh/pull/3261))
- Fixed .ssh folder permissions for Agentless. ([#2660](https://github.com/wazuh/wazuh/pull/2660))
- Fixed repeated fields in SCA summary events. ([#3278](https://github.com/wazuh/wazuh/pull/3278))
- Fixed command output treatment for the SCA module. ([#3297](https://github.com/wazuh/wazuh/pull/3297))
- Fixed _agent_upgrade_ tool to set the manager version as the default one. ([#2721](https://github.com/wazuh/wazuh/pull/2721))
- Fixed execd crash when timeout list is not initialized. ([#3316](https://github.com/wazuh/wazuh/pull/3316))
- Fixed support for reading large files on Windows Logcollector. ([#3248](https://github.com/wazuh/wazuh/pull/3248))
- Fixed the manager restarting process via API on Docker. ([#3273](https://github.com/wazuh/wazuh/pull/3273))
- Fixed the _agent_info_ files synchronization between cluster nodes. ([#3272](https://github.com/wazuh/wazuh/pull/3272))

### Removed

- Removed 5-second reading timeout for File Integrity Monitoring scan. ([#3366](https://github.com/wazuh/wazuh/pull/3366))


## [v3.9.0] - 2019-05-02

### Added

- New module to perform **Security Configuration Assessment** scans. ([#2598](https://github.com/wazuh/wazuh/pull/2598))
- New **Logcollector** features. ([#2929](https://github.com/wazuh/wazuh/pull/2929))
  - Let Logcollector filter files by content. ([#2796](https://github.com/wazuh/wazuh/issues/2796))
  - Added a pattern exclusion option to Logcollector. ([#2797](https://github.com/wazuh/wazuh/issues/2797))
  - Let Logcollector filter files by date. ([#2799](https://github.com/wazuh/wazuh/issues/2799))
  - Let logcollector support wildcards on Windows. ([#2898](https://github.com/wazuh/wazuh/issues/2898))
- **Fluent forwarder** for agents. ([#2828](https://github.com/wazuh/wazuh/issues/2828))
- Collect network and port inventory for Windows XP/Server 2003. ([#2464](https://github.com/wazuh/wazuh/pull/2464))
- Included inventory fields as dynamic fields in events to use them in rules. ([#2441](https://github.com/wazuh/wazuh/pull/2441))
- Added an option _startup_healthcheck_ in FIM so that the the who-data health-check is optional. ([#2323](https://github.com/wazuh/wazuh/pull/2323))
- The real agent IP is reported by the agent and shown in alerts and the App interface. ([#2577](https://github.com/wazuh/wazuh/pull/2577))
- Added support for organizations in AWS wodle. ([#2627](https://github.com/wazuh/wazuh/pull/2627))
- Added support for hot added symbolic links in _Whodata_. ([#2466](https://github.com/wazuh/wazuh/pull/2466))
- Added `-t` option to `wazuh-clusterd` binary ([#2691](https://github.com/wazuh/wazuh/pull/2691)).
- Added options `same_field` and `not_same_field` in rules to correlate dynamic fields between events. ([#2689](https://github.com/wazuh/wazuh/pull/2689))
- Added optional daemons start by default. ([#2769](https://github.com/wazuh/wazuh/pull/2769))
- Make the Windows installer to choose the appropriate `ossec.conf` file based on the System version. ([#2773](https://github.com/wazuh/wazuh/pull/2773))
- Added writer thread preference for Logcollector. ([#2783](https://github.com/wazuh/wazuh/pull/2783))
- Added database deletion from Wazuh-DB for removed agents. ([#3123](https://github.com/wazuh/wazuh/pull/3123))

### Changed

- Introduced a network buffer in Remoted to cache incomplete messages from agents. This improves the performance by preventing Remoted from waiting for complete messages. ([#2528](https://github.com/wazuh/wazuh/pull/2528))
- Improved alerts about disconnected agents: they will contain the data about the disconnected agent, although the alert is actually produced by the manager. ([#2379](https://github.com/wazuh/wazuh/pull/2379))
- PagerDuty integration plain text alert support (by @spartantri). ([#2403](https://github.com/wazuh/wazuh/pull/2403))
- Improved Remoted start-up logging messages. ([#2460](https://github.com/wazuh/wazuh/pull/2460))
- Let _agent_auth_ warn when it receives extra input arguments. ([#2489](https://github.com/wazuh/wazuh/pull/2489))
- Update the who-data related SELinux rules for Audit 3.0. This lets who-data work on Fedora 29. ([#2419](https://github.com/wazuh/wazuh/pull/2419))
- Changed data source for network interface's MAC address in Syscollector so that it will be able to get bonded interfaces' MAC. ([#2550](https://github.com/wazuh/wazuh/pull/2550))
- Migrated unit tests from Check to TAP (Test Anything Protocol). ([#2572](https://github.com/wazuh/wazuh/pull/2572))
- Now labels starting with `_` are reserved for internal use. ([#2577](https://github.com/wazuh/wazuh/pull/2577))
- Now AWS wodle fetches aws.requestParameters.disableApiTermination with an unified format ([#2614](https://github.com/wazuh/wazuh/pull/2614))
- Improved overall performance in cluster ([#2575](https://github.com/wazuh/wazuh/pull/2575))
- Some improvements has been made in the _vulnerability-detector_ module. ([#2603](https://github.com/wazuh/wazuh/pull/2603))
- Refactor of decoded fields from the Windows eventchannel decoder. ([#2684](https://github.com/wazuh/wazuh/pull/2684))
- Deprecate global option `<queue_size>` for Analysisd. ([#2729](https://github.com/wazuh/wazuh/pull/2729))
- Excluded noisy events from Windows Eventchannel. ([#2763](https://github.com/wazuh/wazuh/pull/2763))
- Replaced `printf` functions in `agent-authd`. ([#2830](https://github.com/wazuh/wazuh/pull/2830))
- Replaced `strtoul()` using NULL arguments with `atol()` in wodles config files. ([#2801](https://github.com/wazuh/wazuh/pull/2801))
- Added a more descriptive message for SSL error when agent-auth fails. ([#2941](https://github.com/wazuh/wazuh/pull/2941))
- Changed the starting Analysisd messages about loaded rules from `info` to `debug` level. ([#2881](https://github.com/wazuh/wazuh/pull/2881))
- Re-structured messages for FIM module. ([#2926](https://github.com/wazuh/wazuh/pull/2926))
- Changed `diff` output in Syscheck for Windows. ([#2969](https://github.com/wazuh/wazuh/pull/2969))
- Replaced OSSEC e-mail subject with Wazuh in `ossec-maild`. ([#2975](https://github.com/wazuh/wazuh/pull/2975))
- Added keepalive in TCP to manage broken connections in `ossec-remoted`. ([#3069](https://github.com/wazuh/wazuh/pull/3069))
- Change default restart interval for Docker listener module to one minute. ([#2679](https://github.com/wazuh/wazuh/pull/2679))

### Fixed

- Fixed error in Syscollector for Windows older than Vista when gathering the hardware inventory. ([#2326](https://github.com/wazuh/wazuh/pull/2326))
- Fixed an error in the OSQuery configuration validation. ([#2446](https://github.com/wazuh/wazuh/pull/2446))
- Prevent Integrator, Syslog Client and Mail forwarded from getting stuck while reading _alerts.json_. ([#2498](https://github.com/wazuh/wazuh/pull/2498))
- Fixed a bug that could make an Agent running on Windows XP close unexpectedly while receiving a WPK file. ([#2486](https://github.com/wazuh/wazuh/pull/2486))
- Fixed _ossec-control_ script in Solaris. ([#2495](https://github.com/wazuh/wazuh/pull/2495))
- Fixed a compilation error when building Wazuh in static linking mode with the Audit library enabled. ([#2523](https://github.com/wazuh/wazuh/pull/2523))
- Fixed a memory hazard in Analysisd on log pre-decoding for short logs (less than 5 bytes). ([#2391](https://github.com/wazuh/wazuh/pull/2391))
- Fixed defects reported by Cppcheck. ([#2521](https://github.com/wazuh/wazuh/pull/2521))
  - Double free in GeoIP data handling with IPv6.
  - Buffer overlay when getting OS information.
  - Check for successful memory allocation in Syscollector.
- Fix out-of-memory error in Remoted when upgrading an agent with a big data chunk. ([#2594](https://github.com/wazuh/wazuh/pull/2594))
- Re-registered agent are reassigned to correct groups when the multigroup is empty. ([#2440](https://github.com/wazuh/wazuh/pull/2440))
- Wazuh manager starts regardless of the contents of _local_decoder.xml_. ([#2465](https://github.com/wazuh/wazuh/pull/2465))
- Let _Remoted_ wait for download module availability. ([#2517](https://github.com/wazuh/wazuh/pull/2517))
- Fix duplicate field names at some events for Windows eventchannel. ([#2500](https://github.com/wazuh/wazuh/pull/2500))
- Delete empty fields from Windows Eventchannel alerts. ([#2492](https://github.com/wazuh/wazuh/pull/2492))
- Fixed memory leak and crash in Vulnerability Detector. ([#2620](https://github.com/wazuh/wazuh/pull/2620))
- Prevent Analysisd from crashing when receiving an invalid Syscollector event. ([#2621](https://github.com/wazuh/wazuh/pull/2621))
- Fix a bug in the database synchronization module that left broken references of removed agents to groups. ([#2628](https://github.com/wazuh/wazuh/pull/2628))
- Fixed restart service in AIX. ([#2674](https://github.com/wazuh/wazuh/pull/2674))
- Prevent Execd from becoming defunct when Active Response disabled. ([#2692](https://github.com/wazuh/wazuh/pull/2692))
- Fix error in Syscollector when unable to read the CPU frequency on agents. ([#2740](https://github.com/wazuh/wazuh/pull/2740))
- Fix Windows escape format affecting non-format messages. ([#2725](https://github.com/wazuh/wazuh/pull/2725))
- Avoid a segfault in mail daemon due to the XML tags order in the `ossec.conf`. ([#2711](https://github.com/wazuh/wazuh/pull/2711))
- Prevent the key updating thread from starving in Remoted. ([#2761](https://github.com/wazuh/wazuh/pull/2761))
- Fixed error logging on Windows agent. ([#2791](https://github.com/wazuh/wazuh/pull/2791))
- Let CIS-CAT decoder reuse the Wazuh DB connection socket. ([#2800](https://github.com/wazuh/wazuh/pull/2800))
- Fixed issue with `agent-auth` options without argument. ([#2808](https://github.com/wazuh/wazuh/pull/2808))
- Fixed control of the frequency counter in alerts. ([#2854](https://github.com/wazuh/wazuh/pull/2854))
- Ignore invalid files for agent groups. ([#2895](https://github.com/wazuh/wazuh/pull/2895))
- Fixed invalid behaviour when moving files in Whodata mode. ([#2888](https://github.com/wazuh/wazuh/pull/2888))
- Fixed deadlock in Remoted when updating the `keyentries` structure. ([#2956](https://github.com/wazuh/wazuh/pull/2956))
- Fixed error in Whodata when one of the file permissions cannot be extracted. ([#2940](https://github.com/wazuh/wazuh/pull/2940))
- Fixed System32 and SysWOW64 event processing in Whodata. ([#2935](https://github.com/wazuh/wazuh/pull/2935))
- Fixed Syscheck hang when monitoring system directories. ([#3059](https://github.com/wazuh/wazuh/pull/3059))
- Fixed the package inventory for MAC OS X. ([#3035](https://github.com/wazuh/wazuh/pull/3035))
- Translated the Audit Policy fields from IDs for Windows events. ([#2950](https://github.com/wazuh/wazuh/pull/2950))
- Fixed broken pipe error when Wazuh-manager closes TCP connection. ([#2965](https://github.com/wazuh/wazuh/pull/2965))
- Fixed whodata mode on drives other than the main one. ([#2989](https://github.com/wazuh/wazuh/pull/2989))
- Fixed bug occurred in the database while removing an agent. ([#2997](https://github.com/wazuh/wazuh/pull/2997))
- Fixed duplicated alerts for Red Hat feed in `vulnerability-detector`. ([#3000](https://github.com/wazuh/wazuh/pull/3000))
- Fixed bug when processing symbolic links in Whodata. ([#3025](https://github.com/wazuh/wazuh/pull/3025))
- Fixed option for ignoring paths in rootcheck. ([#3058](https://github.com/wazuh/wazuh/pull/3058))
- Allow Wazuh service on MacOSX to be available without restart. ([#3119](https://github.com/wazuh/wazuh/pull/3119))
- Ensure `internal_options.conf` file is overwritten on Windows upgrades. ([#3153](https://github.com/wazuh/wazuh/pull/3153))
- Fixed the reading of the setting `attempts` of the Docker module. ([#3067](https://github.com/wazuh/wazuh/pull/3067))
- Fix a memory leak in Docker listener module. ([#2679](https://github.com/wazuh/wazuh/pull/2679))


## [v3.8.2] - 2019-01-30

### Fixed

- Analysisd crashed when parsing a log from OpenLDAP due to a bug in the option `<accumulate>`. ([#2456](https://github.com/wazuh/wazuh/pull/2456))
- Modulesd closed unexpectedly if a command was defined without a `<tag>` option. ([#2470](https://github.com/wazuh/wazuh/pull/2470))
- The Eventchannel decoder was not being escaping backslashes correctly. ([#2483](https://github.com/wazuh/wazuh/pull/2483))
- The Eventchannel decoder was leaving spurious trailing spaces in some fields. ([#2484](https://github.com/wazuh/wazuh/pull/2484))


## [v3.8.1] - 2019-01-25

### Fixed

- Fixed memory leak in Logcollector when reading Windows eventchannel. ([#2450](https://github.com/wazuh/wazuh/pull/2450))
- Fixed script parsing error in Solaris 10. ([#2449](https://github.com/wazuh/wazuh/pull/2449))
- Fixed version comparisons on Red Hat systems. (By @orlando-jamie) ([#2445](https://github.com/wazuh/wazuh/pull/2445))


## [v3.8.0] - 2019-01-19

### Added

- Logcollector **extension for Windows eventchannel logs in JSON format.** ([#2142](https://github.com/wazuh/wazuh/pull/2142))
- Add options to detect **attribute and file permission changes** for Windows. ([#1918](https://github.com/wazuh/wazuh/pull/1918))
- Added **Audit health-check** in the Whodata initialization. ([#2180](https://github.com/wazuh/wazuh/pull/2180))
- Added **Audit rules auto-reload** in Whodata. ([#2180](https://github.com/wazuh/wazuh/pull/2180))
- Support for **new AWS services** in the AWS wodle ([#2242](https://github.com/wazuh/wazuh/pull/2242)):
    - AWS Config
    - AWS Trusted Advisor
    - AWS KMS
    - AWS Inspector
    - Add support for IAM roles authentication in EC2 instances.
- New module "Agent Key Polling" to integrate agent key request to external data sources. ([#2127](https://github.com/wazuh/wazuh/pull/2127))
  - Look for missing or old agent keys when Remoted detects an authorization failure.
  - Request agent keys by calling a defined executable or connecting to a local socket.
- Get process inventory for Windows natively. ([#1760](https://github.com/wazuh/wazuh/pull/1760))
- Improved vulnerability detection in Red Hat systems. ([#2137](https://github.com/wazuh/wazuh/pull/2137))
- Add retries to download the OVAL files in vulnerability-detector. ([#1832](https://github.com/wazuh/wazuh/pull/1832))
- Auto-upgrade FIM databases in Wazuh-DB. ([#2147](https://github.com/wazuh/wazuh/pull/2147))
- New dedicated thread for AR command running on Windows agent. ([#1725](https://github.com/wazuh/wazuh/pull/1725))
  -  This will prevent the agent from delaying due to an AR execution.
- New internal option to clean residual files of agent groups. ([#1985](https://github.com/wazuh/wazuh/pull/1985))
- Add a manifest to run `agent-auth.exe` with elevated privileges. ([#1998](https://github.com/wazuh/wazuh/pull/1998))
- Compress `last-entry` files to check differences by FIM. ([#2034](https://github.com/wazuh/wazuh/pull/2034))
- Add error messages to integration scripts. ([#2143](https://github.com/wazuh/wazuh/pull/2143))
- Add CDB lists building on install. ([#2167](https://github.com/wazuh/wazuh/pull/2167))
- Update Wazuh copyright for internal files. ([#2343](https://github.com/wazuh/wazuh/pull/2343))
- Added option to allow maild select the log file to read from. ([#977](https://github.com/wazuh/wazuh/pull/977))
- Add table to control the metadata of the vuln-detector DB. ([#2402](https://github.com/wazuh/wazuh/pull/2402))

### Changed

- Now Wazuh manager can be started with an empty configuration in ossec.conf. ([#2086](https://github.com/wazuh/wazuh/pull/2086))
- The Authentication daemon is now enabled by default. ([#2129](https://github.com/wazuh/wazuh/pull/2129))
- Make FIM show alerts for new files by default. ([#2213](https://github.com/wazuh/wazuh/pull/2213))
- Reduce the length of the query results from Vulnerability Detector to Wazuh DB. ([#1798](https://github.com/wazuh/wazuh/pull/1798))
- Improved the build system to automatically detect a big-endian platform. ([#2031](https://github.com/wazuh/wazuh/pull/2031))
  - Building option `USE_BIG_ENDIAN` is not already needed on Solaris (SPARC) or HP-UX.
- Expanded the regex pattern maximum size from 2048 to 20480 bytes. ([#2036](https://github.com/wazuh/wazuh/pull/2036))
- Improved IP address validation in the option `<white_list>` (by @pillarsdotnet). ([#1497](https://github.com/wazuh/wazuh/pull/1497))
- Improved rule option `<info>` validation (by @pillarsdotnet). ([#1541](https://github.com/wazuh/wazuh/pull/1541))
- Deprecated the Syscheck option `<remove_old_diff>` by making it mandatory. ([#1915](https://github.com/wazuh/wazuh/pull/1915))
- Fix invalid error "Unable to verity server certificate" in _ossec-authd_ (server). ([#2045](https://github.com/wazuh/wazuh/pull/2045))
- Remove deprecated flag `REUSE_ID` from the Makefile options. ([#2107](https://github.com/wazuh/wazuh/pull/2107))
- Syscheck first queue error message changed into a warning. ([#2146](https://github.com/wazuh/wazuh/pull/2146))
- Do the DEB and RPM package scan regardless of Linux distribution. ([#2168](https://github.com/wazuh/wazuh/pull/2168))
- AWS VPC configuration in the AWS wodle ([#2242](https://github.com/wazuh/wazuh/pull/2242)).
- Hide warning log by FIM when cannot open a file that has just been removed. ([#2201](https://github.com/wazuh/wazuh/pull/2201))
- The default FIM configuration will ignore some temporary files. ([#2202](https://github.com/wazuh/wazuh/pull/2202))

### Fixed

- Fixed error description in the osquery configuration parser (by @pillarsdotnet). ([#1499](https://github.com/wazuh/wazuh/pull/1499))
- The FTS comment option `<ftscomment>` was not being read (by @pillarsdotnet). ([#1536](https://github.com/wazuh/wazuh/pull/1536))
- Fixed error when multigroup files are not found. ([#1792](https://github.com/wazuh/wazuh/pull/1792))
- Fix error when assigning multiple groups whose names add up to more than 4096 characters. ([#1792](https://github.com/wazuh/wazuh/pull/1792))
- Replaced "getline" function with "fgets" in vulnerability-detector to avoid compilation errors with older versions of libC. ([#1822](https://github.com/wazuh/wazuh/pull/1822))
- Fix bug in Wazuh DB when trying to store multiple network interfaces with the same IP from Syscollector. ([#1928](https://github.com/wazuh/wazuh/pull/1928))
- Improved consistency of multigroups. ([#1985](https://github.com/wazuh/wazuh/pull/1985))
- Fixed the reading of the OS name and version in HP-UX systems. ([#1990](https://github.com/wazuh/wazuh/pull/1990))
- Prevent the agent from producing an error on platforms that don't support network timeout. ([#2001](https://github.com/wazuh/wazuh/pull/2001))
- Logcollector could not set the maximum file limit on HP-UX platform. ([2030](https://github.com/wazuh/wazuh/pull/2030))
- Allow strings up to 64KB long for log difference analysis. ([#2032](https://github.com/wazuh/wazuh/pull/2032))
- Now agents keep their registration date when upgrading the manager. ([#2033](https://github.com/wazuh/wazuh/pull/2033))
- Create an empty `client.keys` file on a fresh installation of a Windows agent. ([2040](https://github.com/wazuh/wazuh/pull/2040))
- Allow CDB list keys and values to have double quotes surrounding. ([#2046](https://github.com/wazuh/wazuh/pull/2046))
- Remove file `queue/db/.template.db` on upgrade / restart. ([2073](https://github.com/wazuh/wazuh/pull/2073))
- Fix error on Analysisd when `check_value` doesn't exist. ([2080](https://github.com/wazuh/wazuh/pull/2080))
- Prevent Rootcheck from looking for invalid link count in agents running on Solaris (by @ecsc-georgew). ([2087](https://github.com/wazuh/wazuh/pull/2087))
- Fixed the warning messages when compiling the agent on AIX. ([2099](https://github.com/wazuh/wazuh/pull/2099))
- Fix missing library when building Wazuh with MySQL support. ([#2108](https://github.com/wazuh/wazuh/pull/2108))
- Fix compile warnings for the Solaris platform. ([#2121](https://github.com/wazuh/wazuh/pull/2121))
- Fixed regular expression for audit.key in audit decoder. ([#2134](https://github.com/wazuh/wazuh/pull/2134))
- Agent's ossec-control stop should wait a bit after killing a process. ([#2149](https://github.com/wazuh/wazuh/pull/2149))
- Fixed error ocurred while monitoring symbolic links in Linux. ([#2152](https://github.com/wazuh/wazuh/pull/2152))
- Fixed some bugs in Logcollector: ([#2154](https://github.com/wazuh/wazuh/pull/2154))
  - If Logcollector picks up a log exceeding 65279 bytes, that log may lose the null-termination.
  - Logcollector crashes if multiple wildcard stanzas resolve the same file.
  - An error getting the internal file position may lead to an undefined condition.
- Execd daemon now runs even if active response is disabled ([#2177](https://github.com/wazuh/wazuh/pull/2177))
- Fix high precision timestamp truncation in rsyslog messages. ([#2128](https://github.com/wazuh/wazuh/pull/2128))
- Fix missing Whodata section to the remote configuration query. ([#2173](https://github.com/wazuh/wazuh/pull/2173))
- Bugfixes in AWS wodle ([#2242](https://github.com/wazuh/wazuh/pull/2242)):
    - Fixed bug in AWS Guard Duty alerts when there were multiple remote IPs.
    - Fixed bug when using flag `remove_from_bucket`.
    - Fixed bug when reading buckets generating more than 1000 logs in the same day.
    - Increase `qty` of `aws.eventNames` and remove usage of `aws.eventSources`.
- Fix bug in cluster configuration when using Kubernetes ([#2227](https://github.com/wazuh/wazuh/pull/2227)).
- Fix network timeout setup in agent running on Windows. ([#2185](https://github.com/wazuh/wazuh/pull/2185))
- Fix default values for the `<auto_ignore>` option. ([#2210](https://github.com/wazuh/wazuh/pull/2210))
- Fix bug that made Modulesd and Remoted crash on ARM architecture. ([#2214](https://github.com/wazuh/wazuh/pull/2214))
- The regex parser included the next character after a group:
  - If the input string just ends after that character. ([#2216](https://github.com/wazuh/wazuh/pull/2216))
  - The regex parser did not accept a group terminated with an escaped byte or a class. ([#2224](https://github.com/wazuh/wazuh/pull/2224))
- Fixed buffer overflow hazard in FIM when performing change report on long paths on macOS platform. ([#2285](https://github.com/wazuh/wazuh/pull/2285))
- Fix sending of the owner attribute when a file is created in Windows. ([#2292](https://github.com/wazuh/wazuh/pull/2292))
- Fix audit reconnection to the Whodata socket ([#2305](https://github.com/wazu2305h/wazuh/pull/2305))
- Fixed agent connection in TCP mode on Windows XP. ([#2329](https://github.com/wazuh/wazuh/pull/2329))
- Fix log shown when a command reaches its timeout and `ignore_output` is enabled. ([#2316](https://github.com/wazuh/wazuh/pull/2316))
- Analysisd and Syscollector did not detect the number of cores on Raspberry Pi. ([#2304](https://github.com/wazuh/wazuh/pull/2304))
- Analysisd and Syscollector did not detect the number of cores on CentOS 5. ([#2340](https://github.com/wazuh/wazuh/pull/2340))


## [v3.7.2] - 2018-12-17

### Changed

- Logcollector will fully read a log file if it reappears after being deleted. ([#2041](https://github.com/wazuh/wazuh/pull/2041))

### Fixed

- Fix some bugs in Logcollector: ([#2041](https://github.com/wazuh/wazuh/pull/2041))
  - Logcollector ceases monitoring any log file containing a binary zero-byte.
  - If a local file defined with wildcards disappears, Logcollector incorrectly shows a negative number of remaining open attempts.
  - Fixed end-of-file detection for text-based file formats.
- Fixed a bug in Analysisd that made it crash when decoding a malformed FIM message. ([#2089](https://github.com/wazuh/wazuh/pull/2089))


## [v3.7.1] - 2018-12-05

### Added

- New internal option `remoted.guess_agent_group` allowing agent group guessing by Remoted to be optional. ([#1890](https://github.com/wazuh/wazuh/pull/1890))
- Added option to configure another audit keys to monitor. ([#1882](https://github.com/wazuh/wazuh/pull/1882))
- Added option to create the SSL certificate and key with the install.sh script. ([#1856](https://github.com/wazuh/wazuh/pull/1856))
- Add IPv6 support to `host-deny.sh` script. (by @iasdeoupxe). ([#1583](https://github.com/wazuh/wazuh/pull/1583))
- Added tracing information (PID, function, file and line number) to logs when debugging is enabled. ([#1866](https://github.com/wazuh/wazuh/pull/1866))

### Changed

- Change errors messages to descriptive warnings in Syscheck when a files is not reachable. ([#1730](https://github.com/wazuh/wazuh/pull/1730))
- Add default values to global options to let the manager start. ([#1894](https://github.com/wazuh/wazuh/pull/1894))
- Improve Remoted performance by reducing interaction between threads. ([#1902](https://github.com/wazuh/wazuh/pull/1902))

### Fixed

- Prevent duplicates entries for denied IP addresses by `host-deny.sh`. (by @iasdeoupxe). ([#1583](https://github.com/wazuh/wazuh/pull/1583))
- Fix issue in Logcollector when reaching the file end before getting a full line. ([#1744](https://github.com/wazuh/wazuh/pull/1744))
- Throw an error when a nonexistent CDB file is added in the ossec.conf file. ([#1783](https://github.com/wazuh/wazuh/pull/1783))
- Fix bug in Remoted that truncated control messages to 1024 bytes. ([#1847](https://github.com/wazuh/wazuh/pull/1847))
- Avoid that the attribute `ignore` of rules silence alerts. ([#1874](https://github.com/wazuh/wazuh/pull/1874))
- Fix race condition when decoding file permissions. ([#1879](https://github.com/wazuh/wazuh/pull/1879)
- Fix to overwrite FIM configuration when directories come in the same tag separated by commas. ([#1886](https://github.com/wazuh/wazuh/pull/1886))
- Fixed issue with hash table handling in FTS and label management. ([#1889](https://github.com/wazuh/wazuh/pull/1889))
- Fixed id's and description of FIM alerts. ([#1891](https://github.com/wazuh/wazuh/pull/1891))
- Fix log flooding by Logcollector when monitored files disappear. ([#1893](https://github.com/wazuh/wazuh/pull/1893))
- Fix bug configuring empty blocks in FIM. ([#1897](https://github.com/wazuh/wazuh/pull/1897))
- Let the Windows agent reset the random generator context if it's corrupt. ([#1898](https://github.com/wazuh/wazuh/pull/1898))
- Prevent Remoted from logging errors if the cluster configuration is missing or invalid. ([#1900](https://github.com/wazuh/wazuh/pull/1900))
- Fix race condition hazard in Remoted when handling control messages. ([#1902](https://github.com/wazuh/wazuh/pull/1902))
- Fix uncontrolled condition in the vulnerability-detector version checker. ([#1932](https://github.com/wazuh/wazuh/pull/1932))
- Restore support for Amazon Linux in vulnerability-detector. ([#1932](https://github.com/wazuh/wazuh/pull/1932))
- Fixed starting wodles after a delay specified in `interval` when `run_on_start` is set to `no`, on the first run of the agent. ([#1906](https://github.com/wazuh/wazuh/pull/1906))
- Prevent `agent-auth` tool from creating the file _client.keys_ outside the agent's installation folder. ([#1924](https://github.com/wazuh/wazuh/pull/1924))
- Fix symbolic links attributes reported by `syscheck` in the alerts. ([#1926](https://github.com/wazuh/wazuh/pull/1926))
- Added some improvements and fixes in Whodata. ([#1929](https://github.com/wazuh/wazuh/pull/1929))
- Fix FIM decoder to accept Windows user containing spaces. ([#1930](https://github.com/wazuh/wazuh/pull/1930))
- Add missing field `restrict` when querying the FIM configuration remotely. ([#1931](https://github.com/wazuh/wazuh/pull/1931))
- Fix values of FIM scan showed in agent_control info. ([#1940](https://github.com/wazuh/wazuh/pull/1940))
- Fix agent group updating in database module. ([#2004](https://github.com/wazuh/wazuh/pull/2004))
- Logcollector prevents vmhgfs from synchronizing the inode. ([#2022](https://github.com/wazuh/wazuh/pull/2022))
- File descriptor leak that may impact agents running on UNIX platforms. ([#2021](https://github.com/wazuh/wazuh/pull/2021))
- CIS-CAT events were being processed by a wrong decoder. ([#2014](https://github.com/wazuh/wazuh/pull/2014))


## [v3.7.0] - 2018-11-10

### Added

- Adding feature to **remotely query agent configuration on demand.** ([#548](https://github.com/wazuh/wazuh/pull/548))
- **Boost Analysisd performance with multithreading.** ([#1039](https://github.com/wazuh/wazuh/pull/1039))
- Adding feature to **let agents belong to multiple groups.** ([#1135](https://github.com/wazuh/wazuh/pull/1135))
  - API support for multiple groups. ([#1300](https://github.com/wazuh/wazuh/pull/1300) [#1135](https://github.com/wazuh/wazuh/pull/1135))
- **Boost FIM decoding performance** by storing data into Wazuh DB using SQLite databases. ([#1333](https://github.com/wazuh/wazuh/pull/1333))
  - FIM database is cleaned after restarting agent 3 times, deleting all entries that left being monitored.
  - Added script to migrate older Syscheck databases to WazuhDB. ([#1504](https://github.com/wazuh/wazuh/pull/1504)) ([#1333](https://github.com/wazuh/wazuh/pull/1333))
- Added rule testing output when restarting manager. ([#1196](https://github.com/wazuh/wazuh/pull/1196))
- New wodle for **Azure environment log and process collection.** ([#1306](https://github.com/wazuh/wazuh/pull/1306))
- New wodle for **Docker container monitoring.** ([#1368](https://github.com/wazuh/wazuh/pull/1368))
- Disconnect manager nodes in cluster if no keep alive is received or sent during two minutes. ([#1482](https://github.com/wazuh/wazuh/pull/1482))
- API requests are forwarded to the proper manager node in cluster. ([#885](https://github.com/wazuh/wazuh/pull/885))
- Centralized configuration pushed from manager overwrite the configuration of directories that exist with the same path in ossec.conf. ([#1740](https://github.com/wazuh/wazuh/pull/1740))

### Changed

- Refactor Python framework code to standardize database requests and support queries. ([#921](https://github.com/wazuh/wazuh/pull/921))
- Replaced the `execvpe` function by `execvp` for the Wazuh modules. ([#1207](https://github.com/wazuh/wazuh/pull/1207))
- Avoid the use of reference ID in Syscollector network tables. ([#1315](https://github.com/wazuh/wazuh/pull/1315))
- Make Syscheck case insensitive on Windows agent. ([#1349](https://github.com/wazuh/wazuh/pull/1349))
- Avoid conflicts with the size of time_t variable in wazuh-db. ([#1366](https://github.com/wazuh/wazuh/pull/1366))
- Osquery integration updated: ([#1369](https://github.com/wazuh/wazuh/pull/1369))
  - Nest the result data into a "osquery" object.
  - Extract the pack name into a new field.
  - Include the query name in the alert description.
  - Minor fixes.
- Increased AWS S3 database entry limit to 5000 to prevent reprocessing repeated events. ([#1391](https://github.com/wazuh/wazuh/pull/1391))
- Increased the limit of concurrent agent requests: 1024 by default, configurable up to 4096. ([#1473](https://github.com/wazuh/wazuh/pull/1473))
- Change the default vulnerability-detector interval from 1 to 5 minutes. ([#1729](https://github.com/wazuh/wazuh/pull/1729))
- Port the UNIX version of Auth client (_agent_auth_) to the Windows agent. ([#1790](https://github.com/wazuh/wazuh/pull/1790))
  - Support of TLSv1.2 through embedded OpenSSL library.
  - Support of SSL certificates for agent and manager validation.
  - Unify Auth client option set.

### Fixed

- Fixed email_alerts configuration for multiple recipients. ([#1193](https://github.com/wazuh/wazuh/pull/1193))
- Fixed manager stopping when no command timeout is allowed. ([#1194](https://github.com/wazuh/wazuh/pull/1194))
- Fixed getting RAM memory information from mac OS X and FreeBSD agents. ([#1203](https://github.com/wazuh/wazuh/pull/1203))
- Fixed mandatory configuration labels check. ([#1208](https://github.com/wazuh/wazuh/pull/1208))
- Fix 0 value at check options from Syscheck. ([1209](https://github.com/wazuh/wazuh/pull/1209))
- Fix bug in whodata field extraction for Windows. ([#1233](https://github.com/wazuh/wazuh/issues/1233))
- Fix stack overflow when monitoring deep files. ([#1239](https://github.com/wazuh/wazuh/pull/1239))
- Fix typo in whodata alerts. ([#1242](https://github.com/wazuh/wazuh/issues/1242))
- Fix bug when running quick commands with timeout of 1 second. ([#1259](https://github.com/wazuh/wazuh/pull/1259))
- Prevent offline agents from generating vulnerability-detector alerts. ([#1292](https://github.com/wazuh/wazuh/pull/1292))
- Fix empty SHA256 of rotated alerts and log files. ([#1308](https://github.com/wazuh/wazuh/pull/1308))
- Fixed service startup on error. ([#1324](https://github.com/wazuh/wazuh/pull/1324))
- Set connection timeout for Auth server ([#1336](https://github.com/wazuh/wazuh/pull/1336))
- Fix the cleaning of the temporary folder. ([#1361](https://github.com/wazuh/wazuh/pull/1361))
- Fix check_mtime and check_inode views in Syscheck alerts. ([#1364](https://github.com/wazuh/wazuh/pull/1364))
- Fixed the reading of the destination address and type for PPP interfaces. ([#1405](https://github.com/wazuh/wazuh/pull/1405))
- Fixed a memory bug in regex when getting empty strings. ([#1430](https://github.com/wazuh/wazuh/pull/1430))
- Fixed report_changes with a big ammount of files. ([#1465](https://github.com/wazuh/wazuh/pull/1465))
- Prevent Logcollector from null-terminating socket output messages. ([#1547](https://github.com/wazuh/wazuh/pull/1547))
- Fix timeout overtaken message using infinite timeout. ([#1604](https://github.com/wazuh/wazuh/pull/1604))
- Prevent service from crashing if _global.db_ is not created. ([#1485](https://github.com/wazuh/wazuh/pull/1485))
- Set new agent.conf template when creating new groups. ([#1647](https://github.com/wazuh/wazuh/pull/1647))
- Fix bug in Wazuh Modules that tried to delete PID folders if a subprocess call failed. ([#1836](https://github.com/wazuh/wazuh/pull/1836))


## [v3.6.1] - 2018-09-07

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


## [v3.6.0] - 2018-08-29

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
- Fixed `open-scap` deadlock when opening large files. ([#1206](https://github.com/wazuh/wazuh/pull/1206)). Thanks to @juergenc for detecting this issue.


### Removed

- The 'T' multiplier has been removed from option `max_output_size`. ([#1089](https://github.com/wazuh/wazuh/pull/1089))


## [v3.5.0] - 2018-08-10

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
- Deleted agent_list tool, replaced by agent_control. ([ba0265b](https://github.com/wazuh/wazuh/commit/ba0265b6e9e3fed133d60ef2df3450fdf26f7da4#diff-f57f2991a6aa25fe45d8036c51bf8b4d))

## [v3.4.0] - 2018-07-24

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

## [v3.3.1] - 2018-06-18

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


## [v3.3.0] - 2018-06-06

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


## [v3.2.4] - 2018-06-01

### Fixed
- Fixed segmentation fault in maild when `<queue-size>` is included in the global configuration.
- Fixed bug in Framework when retrieving mangers logs. ([#644](https://github.com/wazuh/wazuh/pull/644))
- Fixed bug in clusterd to prevent the synchronization of `.swp` files. ([#694](https://github.com/wazuh/wazuh/pull/694))
- Fixed bug in Framework parsing agent configuration. ([#681](https://github.com/wazuh/wazuh/pull/681))
- Fixed several bugs using python3 with the Python framework. ([#701](https://github.com/wazuh/wazuh/pull/701))


## [v3.2.3] - 2018-05-28

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


## [v3.2.2] - 2018-05-07

### Added

- Created an input queue for Remoted to prevent agent connection starvation. ([#509](https://github.com/wazuh/wazuh/pull/509))

### Changed

- Updated Slack integration. ([#443](https://github.com/wazuh/wazuh/pull/443))
- Increased connection timeout for remote upgrades. ([#480](https://github.com/wazuh/wazuh/pull/480))
- Vulnerability-detector does not stop agents detection if it fails to find the software for one of them.
- Improve the version comparator algorithm in vulnerability-detector. ([#508](https://github.com/wazuh/wazuh/pull/508))

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

## [v3.2.1] - 2018-03-03

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

## [v3.2.0] - 2018-02-13

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

## [v3.1.0] - 2017-12-22

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

## [v3.0.0] - 2017-12-12

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

## [v2.0.0] - 2017-03-14

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

## [v1.1.0] - 2016-04-06

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

## [v1.0.0] - 2015-11-23
- Initial Wazuh version v1.0
