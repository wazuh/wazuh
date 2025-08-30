# API Reference

The Inventory Sync module indexes inventory state data into dedicated indices within the Wazuh-indexer (OpenSearch). The indexed data can be retrieved using the [OpenSearch API](https://opensearch.org/docs/latest/api-reference/).

For querying synchronized inventory data, use the **GET /wazuh-states-*/_search** endpoint pattern.

## Indexed Inventory Data

Below are examples of indexed inventory data following the [ECS](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) and Wazuh Common Schema standards.
