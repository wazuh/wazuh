# API Reference

The Inventory Harvester module indexes Syscheck and Inventory data into dedicated indices within the Wazuh-indexer (OpenSearch). So the information is retrieved by using the Opensearch API (ref: https://opensearch.org/docs/latest/api-reference/).

For a quick reference, the table below lists the component and its specific query.

| Component                    | Query                                  |
|------------------------------|----------------------------------------|
| Inventory OS                 | GET /wazuh-states-system-*/_search     |
| Inventory Packages           | GET /wazuh-states-packages-*/_search   |
| Inventory Processes          | GET /wazuh-states-processes-*/_search  |
| Inventory Ports              | GET /wazuh-states-ports-*/_search      |
| Inventory Hardware           | GET /wazuh-states-hardware-*/_search   |
| Inventory Hotfixes           | GET /wazuh-states-hotfixes-*/_search   |
| Inventory Network Addresses  | GET /wazuh-states-networks-*/_search   |
| Inventory Network Protocols  | GET /wazuh-states-protocols-*/_search  |
| Inventory Network Interfaces | GET /wazuh-states-interfaces-*/_search |
| Syscheck Files               | GET /wazuh-states-files-*/_search      |
| Syscheck Registries          | GET /wazuh-states-registries-*/_search |

Refer to [Description](description.md) to visualize the retrieved document format for each request.
