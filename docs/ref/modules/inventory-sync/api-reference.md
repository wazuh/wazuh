# API Reference

Inventory Sync exposes two API surfaces:

- The **module start/stop interface** used by the Wazuh module loader.
- The **indexed state data surface** exposed through the Wazuh Indexer.

## Module interface

### C entry points

The shared library exports these symbols:

```c
EXPORTED void inventory_sync_start(full_log_fnc_t callbackLog, const cJSON* configuration);
EXPORTED void inventory_sync_stop();
```

The manager-side wrapper in `wm_inventory_sync.c` loads the shared library dynamically and invokes those functions at module start and stop.

### C++ interface

The public C++ facade exposes:

```cpp
class InventorySync final : public Singleton<InventorySync>
{
public:
    void start(const std::function<void(...)>& logFunction,
               const nlohmann::json& configuration) const;
    void stop() const;
};
```

## Runtime protocol surface

The FlatBuffer protocol accepted by Inventory Sync includes:

- `Start`
- `DataValue`
- `DataBatch`
- `DataContext`
- `DataClean`
- `ChecksumModule`
- `End`
- `ReqRet`

Responses produced by the manager include:

- `StartAck`
- `EndAck`
- `ReqRet`

See the FlatBuffers page for the full schema details.

## Indexed state indices

Inventory Sync works against the `wazuh-states-*` family. The currently supported inventory families are:

### Syscollector indices

- `wazuh-states-inventory-system`
- `wazuh-states-inventory-hardware`
- `wazuh-states-inventory-hotfixes`
- `wazuh-states-inventory-packages`
- `wazuh-states-inventory-processes`
- `wazuh-states-inventory-ports`
- `wazuh-states-inventory-interfaces`
- `wazuh-states-inventory-protocols`
- `wazuh-states-inventory-networks`
- `wazuh-states-inventory-users`
- `wazuh-states-inventory-groups`
- `wazuh-states-inventory-services`
- `wazuh-states-inventory-browser-extensions`

### FIM indices

- `wazuh-states-fim-files`
- `wazuh-states-fim-registry-keys`
- `wazuh-states-fim-registry-values`

### SCA index

- `wazuh-states-sca`

### Related downstream index

- `wazuh-states-vulnerabilities`

`wazuh-states-vulnerabilities` is not written directly by Inventory Sync, but it is part of the current manager-side flow because Inventory Sync can trigger vulnerability scans from the same synchronization session.

## Querying synchronized data

State data can be queried through the Wazuh Indexer search API.

### Search all state indices

```http
GET /wazuh-states-*/_search
```

### Search one agent across all state indices

```json
GET /wazuh-states-*/_search
{
  "query": {
    "term": {
      "wazuh.agent.id": "001"
    }
  }
}
```

### Search SCA documents for one agent

```json
GET /wazuh-states-sca/_search
{
  "query": {
    "term": {
      "wazuh.agent.id": "001"
    }
  }
}
```

### Search inventory packages for one agent

```json
GET /wazuh-states-inventory-packages/_search
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "wazuh.agent.id": "001" } },
        { "exists": { "field": "package.name" } }
      ]
    }
  }
}
```

## Indexed document shape

Inventory Sync enriches indexed state documents with manager-side metadata before sending them to the indexer. In practice, upserted documents include at least:

- `wazuh.agent.id`
- `wazuh.agent.name`
- `wazuh.agent.version`
- `wazuh.agent.groups`
- `wazuh.agent.host.architecture`
- `wazuh.agent.host.hostname`
- `wazuh.agent.host.os.*`
- `wazuh.cluster.name`

The domain-specific payload from the agent is then appended to that metadata. A package document, for example, can look like this:

```json
{
  "wazuh": {
    "agent": {
      "id": "001",
      "name": "ubuntu22",
      "version": "v5.0.0",
      "groups": ["default"],
      "host": {
        "architecture": "x86_64",
        "hostname": "ubuntu22",
        "os": {
          "name": "Ubuntu",
          "platform": "ubuntu",
          "type": "linux",
          "version": "22.04.5 LTS"
        }
      }
    },
    "cluster": {
      "name": "cluster"
    }
  },
  "package": {
    "name": "openssl",
    "version": "3.0.2",
    "type": "deb"
  },
  "checksum": {
    "hash": {
      "sha1": "..."
    }
  },
  "state": {
    "modified_at": "2026-04-20T10:00:00.000Z"
  }
}
```
