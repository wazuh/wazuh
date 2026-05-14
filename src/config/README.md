# Wazuh configurations

Wazuh manager and agent configuration are managed and disposed to each module or system component in different ways.

Each module has a different configuration section, for specific information about each section please refer to online documentation.

## Sections

**Vulnerability Detection**

This module uses configuration from XML file "ossec.conf" section "vulnerability-detection".
The management of the configuration is implemented in the file "src/config/wmodules-vulnerability-detection.c".
The function "Read_Vulnerability_Detection" parses the XML section and converts it to a cJSON object that is used by the vulnerability_scanner module. A pod structure "wm_vulnerability_scanner_t" is used as the converted configuration output.
This pod structure is stored in the "data" field of the vulnerability-detection wmodule.

**Indexer**

This module uses configuration from XML file "ossec.conf" section "indexer".
The management of the configuration is implemented in the file "src/config/indexer-config.c".
The function "Read_Indexer" parses the XML section and converts it to a cJSON object that is used by the vulnerability_scanner module. A cJSON global variable is used as the converted configuration output.
This configuration data has 2 special array fields "hosts" and "certificate_authorities", These fields are stored as an array ignoring the name of the inside elements.

## Documentation

* [Configuration documentation](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html)