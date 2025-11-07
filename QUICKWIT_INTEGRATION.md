# Wazuh - Quickwit Integration

This document describes the integration of Quickwit as a storage backend for Wazuh logs and alerts.

## Overview

Quickwit is a cloud-native search engine optimized for logs and traces. This integration allows Wazuh to use Quickwit as an alternative to OpenSearch/Elasticsearch for storing and querying security events.

## Features

- **Drop-in replacement**: Seamlessly switch between OpenSearch and Quickwit backends
- **Factory pattern**: Automatic connector selection based on configuration
- **NDJSON ingestion**: Efficient bulk indexing using Quickwit's native format
- **Python SDK**: Full-featured client for queries and dashboard integration
- **Dashboard support**: Pre-built utilities for common security analytics queries

## Architecture

### Components

1. **QuickwitConnectorAsync** (`src/shared_modules/indexer_connector/`)
   - Async HTTP client for Quickwit ingest API
   - Bulk document indexing with NDJSON format
   - Connection pooling and failover support

2. **WQuickwitConnector** (`src/engine/source/wiconnector/`)
   - Implements `IWIndexerConnector` interface
   - Thread-safe wrapper for async operations
   - Integrates with Wazuh engine

3. **ConnectorFactory** (`src/engine/source/wiconnector/`)
   - Factory pattern for backend selection
   - Supports "opensearch" and "quickwit" types
   - Backward compatible (defaults to OpenSearch)

4. **Python SDK** (`framework/wazuh/quickwit/`)
   - `QuickwitClient`: REST API client
   - `QuickwitDashboard`: Dashboard utilities and aggregations

## Configuration

### Basic Configuration

Edit `/var/ossec/etc/ossec.conf` (or use `etc/ossec-quickwit.conf` as a template):

```xml
<ossec_config>
  <indexer>
    <enabled>yes</enabled>
    <type>quickwit</type>
    <hosts>
      <host>http://localhost:7280</host>
    </hosts>
  </indexer>
</ossec_config>
```

### Configuration Options

| Option | Description | Required | Default |
|--------|-------------|----------|---------|
| `enabled` | Enable/disable indexer | Yes | `no` |
| `type` | Backend type (`opensearch` or `quickwit`) | No | `opensearch` |
| `hosts` | List of Quickwit server URLs | Yes | - |
| `username` | Authentication username | No | - |
| `password` | Authentication password | No | - |
| `ssl.certificate_authorities` | CA certificate paths | No | - |
| `ssl.certificate` | Client certificate path | No | - |
| `ssl.key` | Client key path | No | - |

### SSL/TLS Configuration

For HTTPS connections:

```xml
<indexer>
  <enabled>yes</enabled>
  <type>quickwit</type>
  <hosts>
    <host>https://quickwit.example.com:7280</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/etc/ssl/certs/ca-bundle.pem</ca>
    </certificate_authorities>
    <certificate>/etc/wazuh/certs/client.pem</certificate>
    <key>/etc/wazuh/certs/client-key.pem</key>
  </ssl>
</indexer>
```

## Quickwit Setup

### 1. Install Quickwit

```bash
# Download and extract Quickwit
curl -L https://github.com/quickwit-oss/quickwit/releases/latest/download/quickwit-latest-x86_64-unknown-linux-gnu.tar.gz | tar -xz
cd quickwit-*

# Start Quickwit server
./quickwit run
```

### 2. Create Wazuh Index

Create an index configuration file `wazuh-alerts-index.yaml`:

```yaml
version: 0.7

index_id: wazuh-alerts

doc_mapping:
  field_mappings:
    - name: timestamp
      type: datetime
      input_formats:
        - rfc3339
      fast: true

    - name: agent.id
      type: text
      tokenizer: raw
      fast: true

    - name: agent.name
      type: text
      tokenizer: default

    - name: rule.id
      type: u64
      fast: true

    - name: rule.level
      type: u64
      fast: true

    - name: rule.description
      type: text
      tokenizer: default

    - name: data
      type: json

    - name: full_log
      type: text
      tokenizer: default

  timestamp_field: timestamp
  mode: dynamic

indexing_settings:
  commit_timeout_secs: 10

search_settings:
  default_search_fields: [full_log, rule.description]
```

Create the index:

```bash
./quickwit index create --index-config wazuh-alerts-index.yaml
```

### 3. Restart Wazuh

```bash
systemctl restart wazuh-manager
```

## Python SDK Usage

### Basic Search

```python
from wazuh.quickwit.client import QuickwitClient

# Initialize client
client = QuickwitClient(hosts=["http://localhost:7280"])

# Search for high severity alerts
results = client.search(
    index="wazuh-alerts",
    query="rule.level:>=12",
    max_hits=100
)

print(f"Found {results['num_hits']} critical alerts")
for hit in results['hits']:
    print(f"  - {hit['rule.description']}")
```

### Dashboard Integration

```python
from wazuh.quickwit.client import QuickwitClient
from wazuh.quickwit.dashboard import QuickwitDashboard

client = QuickwitClient(hosts=["http://localhost:7280"])
dashboard = QuickwitDashboard(client)

# Get alert summary for last 24 hours
summary = dashboard.get_alerts_summary(
    index="wazuh-alerts",
    time_range_hours=24,
    group_by="rule.level"
)

print(f"Total alerts: {summary['total_alerts']}")

# Get top 10 agents by alert count
top_agents = dashboard.get_top_agents(limit=10)
for agent in top_agents:
    print(f"Agent {agent['agent_id']}: {agent['alert_count']} alerts")

# Get critical alerts
critical = dashboard.get_critical_alerts(min_level=12, max_hits=50)
print(f"Found {len(critical)} critical alerts")
```

### Time-based Queries

```python
from datetime import datetime, timedelta

# Search last hour
end_time = datetime.utcnow()
start_time = end_time - timedelta(hours=1)

results = client.search(
    index="wazuh-alerts",
    query="rule.id:5715",  # SSH authentication success
    start_timestamp=int(start_time.timestamp()),
    end_timestamp=int(end_time.timestamp()),
    max_hits=1000
)
```

## Performance Tuning

### Indexing Performance

- **Batch size**: Quickwit recommends batches of 5,000-10,000 documents
- **Commit strategy**: Use `commit=auto` for automatic commit optimization
- **Concurrent indexing**: Multiple indices can be ingested in parallel

### Query Performance

- Use timestamp-based filtering for time-series data
- Leverage fast fields for aggregations (`fast: true` in index config)
- Use the `sort_by` parameter for efficient sorting

## Monitoring

### Check Cluster Health

```bash
curl http://localhost:7280/api/v1/cluster
```

### View Index Stats

```bash
curl http://localhost:7280/api/v1/indexes/wazuh-alerts
```

### Wazuh Logs

Monitor Wazuh logs for indexer status:

```bash
tail -f /var/ossec/logs/ossec.log | grep -i "quickwit\|indexer"
```

## Troubleshooting

### Connection Issues

1. Verify Quickwit is running:
   ```bash
   curl http://localhost:7280/health
   ```

2. Check Wazuh indexer configuration:
   ```bash
   grep -A 10 "<indexer>" /var/ossec/etc/ossec.conf
   ```

3. Review Wazuh logs:
   ```bash
   tail -n 100 /var/ossec/logs/ossec.log
   ```

### Index Not Created

Ensure the index exists in Quickwit before starting Wazuh:

```bash
./quickwit index list
```

### Performance Issues

- Increase Quickwit resources (memory, CPU)
- Adjust commit timeout in index configuration
- Monitor disk I/O and network latency

## Migration from OpenSearch

1. **Export existing data** (optional):
   ```bash
   # Use elasticdump or similar tool to export from OpenSearch
   ```

2. **Update configuration**:
   - Change `<type>` from `opensearch` to `quickwit`
   - Update `<hosts>` to Quickwit endpoints

3. **Restart Wazuh**:
   ```bash
   systemctl restart wazuh-manager
   ```

4. **Verify indexing**:
   - Check Quickwit UI: http://localhost:7280
   - Query recent alerts using Python SDK

## API Reference

### QuickwitClient Methods

- `search(index, query, max_hits, ...)`: Search documents
- `get_index_metadata(index)`: Get index information
- `list_indices()`: List all indices
- `create_index(config)`: Create new index
- `health_check()`: Check cluster health

### QuickwitDashboard Methods

- `get_alerts_summary(...)`: Aggregated alert statistics
- `get_top_agents(...)`: Top agents by alert count
- `get_alert_timeline(...)`: Time-series alert data
- `get_critical_alerts(...)`: High-severity alerts
- `get_rule_statistics(...)`: Rule triggering statistics
- `get_agent_statistics(agent_id)`: Per-agent statistics

## Contributing

To extend the Quickwit integration:

1. **C++ connectors**: `src/shared_modules/indexer_connector/`
2. **Engine integration**: `src/engine/source/wiconnector/`
3. **Python SDK**: `framework/wazuh/quickwit/`

## License

Copyright (C) 2015, Wazuh Inc.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.

## Support

- Wazuh Documentation: https://documentation.wazuh.com
- Quickwit Documentation: https://quickwit.io/docs
- Wazuh GitHub: https://github.com/wazuh/wazuh
- Quickwit GitHub: https://github.com/quickwit-oss/quickwit
