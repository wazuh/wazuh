# Wazuh configurations

Wazuh manager and agent configuration are managed and disposed to each module or system component in different ways.

Each module has a different configuration section, for specific information about each section please refer to online documentation.

## Sections

**Vulnerability Detection**

This module uses configuration from XML file "ossec.conf" section "vulnerability-detection".
The management of the configuration is implemented in the file "src/config/src/wmodules-vulnerability-detection.c".
The function "Read_Vulnerability_Detection" parses the XML section and converts it to a cJSON object that is used by the vulnerability_scanner module. A pod structure "wm_vulnerability_scanner_t" is used as the converted configuration output.

On the manager the section comes from `etc/wazuh-manager.yml` instead: "Read_Vulnerability_Detection_JSON" (same file) receives the effective `vulnerability-detection` section (see `mconf-config.h`) and hands it to the module as-is — native types (`enabled` boolean, `pageSize`/`numSlices` integers, `feed-update-interval` string). A missing section creates no module.
This pod structure is stored in the "data" field of the vulnerability-detection wmodule.

**Indexer**

This module uses configuration from XML file "ossec.conf" section "indexer".
The management of the configuration is implemented in the file "src/config/src/indexer-config.c".
The function "Read_Indexer" is a thin wrapper that delegates the actual parsing to "get_indexer_cnf()", defined in "src/shared/src/engine_external.c". This function parses the XML section and converts it to a cJSON object that is used by the vulnerability_scanner module. A cJSON global variable is used as the converted configuration output.

On the manager "Read_Indexer_JSON" (same file) fills the same `indexer_config` global from the effective `indexer` section of `etc/wazuh-manager.yml`; a missing section or an empty `hosts` list leaves it `NULL`, which every consumer already treats as "no indexer configured". The `agent-upgrade` and `task-manager` sections have their YAML readers next to the XML ones ("wm_agent_upgrade_read_json", "wm_task_manager_read_json"); modulesd (`wm_config()`) wires the four of them.
This configuration data has 2 special array fields "hosts" and "certificate_authorities", These fields are stored as an array ignoring the name of the inside elements.

## Documentation

* [Configuration documentation](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html)