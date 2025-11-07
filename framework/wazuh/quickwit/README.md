# Wazuh Quickwit Python SDK

Python client library for interacting with Quickwit from Wazuh.

## Installation

The Quickwit SDK is included with Wazuh framework. If you need to install dependencies separately:

```bash
pip install requests
```

## Quick Start

```python
from wazuh.quickwit.client import QuickwitClient
from wazuh.quickwit.dashboard import QuickwitDashboard

# Create client
client = QuickwitClient(hosts=["http://localhost:7280"])

# Search alerts
results = client.search(
    index="wazuh-alerts",
    query="rule.level:>=10",
    max_hits=100
)

print(f"Found {results['num_hits']} alerts")

# Use dashboard utilities
dashboard = QuickwitDashboard(client)
summary = dashboard.get_alerts_summary(time_range_hours=24)
print(f"Total alerts in last 24h: {summary['total_alerts']}")
```

## Modules

### `client.py`

Main client for Quickwit REST API operations.

**Key Classes:**
- `QuickwitClient`: REST API client with search, index management, and cluster operations

**Methods:**
- `search()`: Search documents with query string
- `search_post()`: Search with POST body
- `get_index_metadata()`: Get index information
- `list_indices()`: List all indices
- `create_index()`: Create new index
- `delete_index()`: Delete index
- `cluster_info()`: Get cluster information
- `health_check()`: Check cluster health

### `dashboard.py`

Dashboard utilities for common security analytics queries.

**Key Classes:**
- `QuickwitDashboard`: Pre-built queries for dashboards

**Methods:**
- `get_alerts_summary()`: Aggregated alert statistics
- `get_top_agents()`: Top agents by alert count
- `get_alert_timeline()`: Time-series alert counts
- `get_critical_alerts()`: High-severity alerts
- `get_rule_statistics()`: Rule triggering stats
- `get_agent_statistics()`: Per-agent statistics
- `search_events()`: Custom event search

## Examples

### Basic Search

```python
from wazuh.quickwit.client import QuickwitClient

client = QuickwitClient(hosts=["http://localhost:7280"])

# Simple text search
results = client.search(
    index="wazuh-alerts",
    query="authentication failed",
    max_hits=50
)

# Field-specific search
results = client.search(
    index="wazuh-alerts",
    query="agent.id:001 AND rule.level:>=12",
    max_hits=100
)
```

### Time-based Queries

```python
from datetime import datetime, timedelta

end_time = datetime.utcnow()
start_time = end_time - timedelta(hours=6)

results = client.search(
    index="wazuh-alerts",
    query="rule.id:5715",
    start_timestamp=int(start_time.timestamp()),
    end_timestamp=int(end_time.timestamp()),
    sort_by="-timestamp"  # Most recent first
)
```

### Dashboard Analytics

```python
from wazuh.quickwit.dashboard import QuickwitDashboard

dashboard = QuickwitDashboard(client)

# Get alert summary
summary = dashboard.get_alerts_summary(
    time_range_hours=24,
    group_by="rule.level"
)

# Top 10 agents
top_agents = dashboard.get_top_agents(limit=10)
for agent in top_agents:
    print(f"{agent['agent_id']}: {agent['alert_count']} alerts")

# Critical alerts
critical = dashboard.get_critical_alerts(
    min_level=12,
    max_hits=50
)

# Agent-specific stats
agent_stats = dashboard.get_agent_statistics(
    agent_id="001",
    time_range_hours=24
)
```

### Index Management

```python
# List all indices
indices = client.list_indices()
for idx in indices:
    print(f"Index: {idx['index_id']}")

# Get index metadata
metadata = client.get_index_metadata("wazuh-alerts")
print(f"Index: {metadata['index_id']}")
print(f"Fields: {metadata['doc_mapping']['field_mappings']}")

# Create new index
config = {
    "version": "0.7",
    "index_id": "wazuh-custom",
    "doc_mapping": {
        "field_mappings": [
            {"name": "timestamp", "type": "datetime", "fast": True},
            {"name": "message", "type": "text"}
        ],
        "timestamp_field": "timestamp"
    }
}
client.create_index(config)
```

### Authentication

```python
# With authentication
client = QuickwitClient(
    hosts=["https://quickwit.example.com:7280"],
    username="admin",
    password="secret",
    verify_ssl=True,
    ca_certs="/path/to/ca-bundle.pem"
)
```

## Query Syntax

Quickwit supports a powerful query language:

```python
# Field queries
"agent.id:001"
"rule.level:10"

# Range queries
"rule.level:>=12"
"rule.level:[10 TO 15]"

# Boolean operators
"agent.id:001 AND rule.level:>=10"
"authentication OR authorization"
"rule.id:5715 NOT agent.id:002"

# Wildcard queries
"agent.name:web-*"
"rule.description:*failed*"

# Phrase queries
'"authentication failed"'

# Existence queries
"agent.ip:*"  # Documents with agent.ip field
```

## Error Handling

```python
import requests

try:
    results = client.search("wazuh-alerts", query="test")
except requests.RequestException as e:
    print(f"Request failed: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Configuration from File

```python
import json
from wazuh.quickwit.client import create_client_from_config

# Load from JSON config
with open('/etc/wazuh/quickwit.json') as f:
    config = json.load(f)

client = create_client_from_config(config)
```

Example config file:
```json
{
  "hosts": ["http://localhost:7280"],
  "username": "admin",
  "password": "secret",
  "ssl": {
    "certificate_authorities": ["/path/to/ca.pem"]
  }
}
```

## Performance Tips

1. **Use time-based filtering**: Always specify `start_timestamp` and `end_timestamp` for time-series queries
2. **Limit results**: Use `max_hits` to limit the number of results returned
3. **Pagination**: Use `start_offset` for pagination instead of fetching all results
4. **Field filtering**: Request only needed fields when possible
5. **Connection pooling**: Reuse the same `QuickwitClient` instance

## API Reference

See the main documentation at `/QUICKWIT_INTEGRATION.md` for complete API reference and integration guide.

## License

Copyright (C) 2015, Wazuh Inc.
Licensed under GPLv2.
