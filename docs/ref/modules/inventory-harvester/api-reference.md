# API Reference

The Inventory Harvester module indexes FIM and Inventory data into dedicated indices within the Wazuh-indexer (OpenSearch). So the information is retrieved by using the Opensearch API (ref: https://opensearch.org/docs/latest/api-reference/).

For a quick reference, the table below lists the component and its specific query.

| Component                    | Query                                            |
|------------------------------|--------------------------------------------------|
| Inventory OS                 | GET /wazuh-states-inventory-system-*/_search     |
| Inventory Packages           | GET /wazuh-states-inventory-packages-*/_search   |
| Inventory Processes          | GET /wazuh-states-inventory-processes-*/_search  |
| Inventory Ports              | GET /wazuh-states-inventory-ports-*/_search      |
| Inventory Hardware           | GET /wazuh-states-inventory-hardware-*/_search   |
| Inventory Hotfixes           | GET /wazuh-states-inventory-hotfixes-*/_search   |
| Inventory Network Addresses  | GET /wazuh-states-inventory-networks-*/_search   |
| Inventory Network Protocols  | GET /wazuh-states-inventory-protocols-*/_search  |
| Inventory Network Interfaces | GET /wazuh-states-inventory-interfaces-*/_search |
| Inventory Users              | GET /wazuh-states-inventory-users-*/_search      |
| Inventory Groups             | GET /wazuh-states-inventory-groups-*/_search     |
| FIM Files                    | GET /wazuh-states-fim-files-*/_search            |
| FIM Registries               | GET /wazuh-states-fim-registries-*/_search       |

Refer to [Description](description.md) to visualize the retrieved document format for each request.
