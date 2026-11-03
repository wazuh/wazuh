# Migration

This section contains migration guides for changes that require manual review when moving between major Wazuh versions.

## Wazuh 4.x → 5.0

Start with the manager procedure; it orders the other guides as you need them.

| Guide | Description |
|-------|-------------|
| [Manager migration from 4.x to 5.0](manager-4x-to-5x.md) | The end-to-end procedure: what to back up on 4.x, how to carry agent keys, registry, groups, enrollment password and API users into a fresh 5.0 manager, how 4.x agents behave meanwhile, and how to upgrade and retire the legacy channel |
| [Manager configuration migration](manager-configuration-migration.md) | How to migrate `ossec.conf`, `internal_options.conf`, `api.yaml`, and `cluster.json` from 4.x to 5.x |
| [Agent-manager protocol migration](agent-manager-protocol.md) | The move from the AES TCP/UDP protocol on 1514 to the HTTPS agent API on 1517: ports, message mapping, authentication, and retiring the legacy channel |
| [Agent upgrade 4.x to 5.x](upgrade-4x-to-5x.md) | Upgrading an agent in place: version path, `ossec.conf` changes, startup warnings, TLS requirements |
| [Remote agent upgrade](remote-agent-upgrade.md) | TCP connectivity and version path requirements for remote agent upgrades to 5.x |
| [Agent groups migration](agent-groups-migration.md) | Transferring group configurations when agents are re-enrolled under 5.0 instead of carrying their keys |
| [Rules 4.x to 5.x](rules-4x-to-5x.md) | Translating custom XML rules into engine decoders and Sigma-based detection rules |
| [XML decoders to YAML decoders](xml-decoders-migration.md) | How to migrate decoders from XML to YAML |
| [CDB to KVDB migration](cdb-to-kvdb-migration.md) | Migrating CDB files to KVDB files |
| [Active response](active-response.md) | Active response is rebuilt in 5.x: dashboard-managed channels replace the `ossec.conf` blocks, `ar.conf` and the `PUT /active-response` API |
| [CIS-CAT/OpenSCAP to SCA](ciscat-openscap-to-sca.md) | Replacing CIS-CAT and OpenSCAP wodles with the native SCA module |
| [SCA policies 4.x to 5.x](sca-policies-4x-to-5x.md) | Custom SCA policy format changes |
| [Mail forwarding and reporting](mail-forwarding-reporting.md) | Replacing the removed email functionality |
| [Remote syslog output](remote-syslog-output.md) | Replacing the removed `<syslog_output>` forwarding (`csyslogd`) with dashboard notifications |
| [Integratord to notifications plugin](integratord-notifications.md) | Replacing the removed integrations daemon |
| [Syslog input](syslog-input-4x-to-5x.md) | Receiving syslog through Logcollector with rsyslog |
| [osQuery to IT hygiene](osquery-to-it-hygiene.md) | Replacing the osQuery module |
| [Agentless to supported alternatives](agentless-4x-to-5x.md) | Replacing the removed Agentless module with agent-based and SSH relay approaches |
| [VirusTotal migration](virustotal-migration.md) | Replacing the removed VirusTotal integration |
| [Vulnerability Detection to CTI-based feeds](vulnerability-detection-cti-feeds.md) | Removal of offline feeds and the new CTI/Indexer content distribution model |
| [Filebeat to Indexer Connector](filebeat-to-indexer-connector.md) | The manager writes to the indexer directly; Filebeat is removed |
