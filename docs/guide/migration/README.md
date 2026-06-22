# Migration

This section contains migration guides for changes that require manual review when moving between major Wazuh versions.

## Wazuh 4.x → 5.0

| Guide | Description |
|-------|-------------|
| [Manager configuration migration](manager-configuration-migration.md) | How to migrate `ossec.conf`, `internal_options.conf`, `api.yaml`, and `cluster.json` from 4.x to 5.x |
| [Agent groups migration](agent-groups-migration.md) | How to transfer group configurations and re-enroll agents under 5.0 |
| [CIS-CAT/OpenSCAP to SCA](ciscat-openscap-to-sca.md) | Replacing CIS-CAT and OpenSCAP wodles with the native SCA module |
| [SCA policies 4.x to 5.x](sca-policies-4x-to-5x.md) | Custom SCA policy format changes |
| [Mail forwarding and reporting](mail-forwarding-reporting.md) | Replacing the removed email functionality |
| [osQuery to IT hygiene](osquery-to-it-hygiene.md) | Replacing the osQuery module |
| [VirusTotal migration](virustotal-migration.md) | Replacing the removed VirusTotal integration |
| [Vulnerability Detection to CTI-based feeds](vulnerability-detection-cti-feeds.md) | Removal of offline feeds and the new CTI/Indexer content distribution model |
| [Remote agent upgrade](remote-agent-upgrade.md) | TCP connectivity and version path requirements for remote agent upgrades to 5.x |
| [CDB to KVDB migration](cdb-to-kvdb-migration.md) | Migrating CDB files to KVDB files |
| [Coordinator migration](manager-coordinator-migration.md) | How to migrate HAProxy from 4.x to 5.x |
| [XML decoders to YAML decoders](xml-decoders-migration.md) | How to migrate decoders from XML to YAML |
