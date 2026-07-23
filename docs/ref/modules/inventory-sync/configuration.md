# Configuration

Inventory Sync does not use its own `<inventory_sync>` block in `wazuh-manager.conf`, but it is not configuration-free. At startup, the manager wrapper builds a JSON configuration object and passes it into the shared library.

## Configuration sources

The runtime configuration passed to Inventory Sync contains:

- **`indexer`**: duplicated from the manager indexer configuration.
- **`clusterName`**: the manager cluster name.
- **`clusterNodeName`**: the local manager node name.
- **`maxSessions`**: the session cap derived from internal options.
- **`queueSize`**: the input worker queue cap derived from internal options.
- **`dataValueQuota`**: the global `DataValue` quota derived from internal options.
- **`indexerBulkSize`**: the indexer bulk-size threshold (bytes) derived from internal options. Forwarded to the Indexer Connector as `max_bulk_size`.
- **`indexerFlushInterval`**: the indexer periodic flush interval (seconds) derived from internal options. Forwarded to the Indexer Connector as `flush_interval_seconds`.

The module refuses to start if `clusterName` is missing.

## Indexer configuration

Inventory Sync depends on the manager indexer configuration because all indexing, delete-by-query, search, and update-by-query operations are delegated to the Indexer Connector.

Example configuration payload passed to the module:

```json
{
  "indexer": {
    "hosts": ["https://127.0.0.1:9200"],
    "ssl": {
      "certificate_authorities": [
        "/var/wazuh-manager/etc/certs/root-ca.pem"
      ],
      "certificate": "/var/wazuh-manager/etc/certs/manager.pem",
      "key": "/var/wazuh-manager/etc/certs/manager-key.pem"
    }
  },
  "clusterName": "wazuh",
  "clusterNodeName": "node01",
  "maxSessions": 1000,
  "queueSize": 1000,
  "dataValueQuota": 250000,
  "indexerBulkSize": 10485760,
  "indexerFlushInterval": 20
}
```

## Internal options

### Maximum sessions

Inventory Sync reads the session cap from the internal option `wazuh_modules.max_sessions`.

Current manager-side behavior:

- Allowed range: `1` to `100000`.
- Default on manager builds: `1000`.
- New Start messages are rejected when the active session count reaches that limit.

### Input worker queue size

- **Default value:** `1000`
- **Allowed values:** `1` to `100000`
- **Note:** New Start messages are rejected when active session count reaches this limit

When the session limit is reached, incoming Start messages receive `Status_Offline` responses, causing agents to retry later.

### wazuh_modules.inventory_sync_queue_size

Input worker queue capacity for buffering incoming router messages.

```ini
wazuh_modules.inventory_sync_queue_size=1000
```

- **Default value:** `1000`
- **Allowed values:** `100` to `1000000`
- **Note:** Messages are dropped when queue is full

When the queue reaches capacity:
- Incoming messages are dropped
- A warning is logged for the first drop
- Subsequent warnings are suppressed for 90 seconds to prevent log flooding

### wazuh_modules.inventory_sync_data_value_quota

Global DataValue quota limiting total items across all active sessions.

```ini
wazuh_modules.inventory_sync_data_value_quota=250000
```

- **Default value:** `250000`
- **Allowed values:** `1` to `1000000000`
- **Note:** Quota is reserved on session Start and returned on session End

When a Start message arrives:
- The `size` field value is reserved from the quota
- If insufficient quota remains, the Start message is rejected with `Status_Offline`
- On session end (success, error, stale cleanup, timeout), the reservation is returned
- Quota-rejection events are always logged (no rate limiting)

### wazuh_modules.inventory_sync_indexer_bulk_size_bytes

Indexer bulk-size threshold in bytes for triggering synchronous flush.

```ini
wazuh_modules.inventory_sync_indexer_bulk_size_bytes=10485760
```

- **Default value:** `10485760` (10 MB)
- **Allowed values:** `4096` to `104857600` (4 KB to 100 MB)
- **Note:** Forwarded to Indexer Connector as `max_bulk_size`

The value bounds the NDJSON payload size accumulated before a synchronous flush to wazuh-indexer is triggered. This setting applies independently of other connector instances (e.g., vulnerability scanner has its own `wazuh_modules.indexer_bulk_size_bytes`).

### wazuh_modules.inventory_sync_indexer_flush_interval

Indexer periodic flush interval in seconds.

```ini
wazuh_modules.inventory_sync_indexer_flush_interval=20
```

- **Default value:** `20` seconds
- **Allowed values:** `1` to `3600` (1 second to 1 hour)
- **Note:** Forwarded to Indexer Connector as `flush_interval_seconds`

Drives the background timer that flushes the bulk buffer when the size threshold has not been reached. When the timer fires on an empty buffer, no HTTP request is issued.

---

## Configuration Examples

### Default Configuration

Standard inventory sync settings for most deployments (these are the compiled-in defaults):

```ini
# Maximum concurrent sessions
wazuh_modules.max_sessions=1000

# Input queue capacity
wazuh_modules.inventory_sync_queue_size=1000

# Global DataValue quota
wazuh_modules.inventory_sync_data_value_quota=250000

# Indexer bulk size (10 MB)
wazuh_modules.inventory_sync_indexer_bulk_size_bytes=10485760

# Indexer flush interval (20 seconds)
wazuh_modules.inventory_sync_indexer_flush_interval=20
```

### High-Capacity Configuration

For large deployments with many agents:

```ini
# Support more concurrent sessions
wazuh_modules.max_sessions=5000

# Larger queue buffer
wazuh_modules.inventory_sync_queue_size=50000

# Larger DataValue quota
wazuh_modules.inventory_sync_data_value_quota=2000000

# Larger bulk size for better throughput
wazuh_modules.inventory_sync_indexer_bulk_size_bytes=20971520

# Faster flush for lower latency
wazuh_modules.inventory_sync_indexer_flush_interval=10
```

### Low-Resource Configuration

For resource-constrained environments:

```ini
# Limit concurrent sessions
wazuh_modules.max_sessions=500

# Smaller queue buffer
wazuh_modules.inventory_sync_queue_size=5000

# Smaller DataValue quota
wazuh_modules.inventory_sync_data_value_quota=250000

# Smaller bulk size
wazuh_modules.inventory_sync_indexer_bulk_size_bytes=5242880

# Less frequent flush to reduce overhead
wazuh_modules.inventory_sync_indexer_flush_interval=30
```

### Development Configuration

Optimized for testing and development:

```ini
# Moderate session limit
wazuh_modules.max_sessions=100

# Moderate queue size
wazuh_modules.inventory_sync_queue_size=1000

# Moderate quota
wazuh_modules.inventory_sync_data_value_quota=50000

# Small bulk size for quick feedback
wazuh_modules.inventory_sync_indexer_bulk_size_bytes=1048576

# Fast flush for immediate indexing
wazuh_modules.inventory_sync_indexer_flush_interval=5
```

---

## Operational Constants

The current implementation also relies on fixed runtime constants.

| Parameter | Current Behavior |
|-----------|------------------|
| Router topic (inbound) | `inventory-states` |
| Subscriber ID | `inventory-sync-module` |
| Response transport (outbound) | AR datagram socket `queue/sockets/ar` (`msg_to_agent` framing, `<module>_sync` tag) |
| Keystore socket | `queue/sockets/keystore` |
| RocksDB path | `queue/inventory_sync/` (relative to the manager home) |
| Input worker threads | `cpp_get_nproc()` |
| Indexer-completion worker threads | `1` (serialized) |
| Cleanup sweep interval | `DEFAULT_TIME = 10 minutes` |
| Stale session cleanup threshold | `DEFAULT_TIME * 2 = 20 minutes` without activity |
| Wait for metadata or group reconciliation | Up to `60 seconds` for other sessions of same agent |
| ModuleCheck checksum retries | `5` attempts, `10 s` apart |

---

## Session storage

Inventory Sync stores in-flight session data in RocksDB under `queue/inventory_sync/` (the `INVENTORY_SYNC_PATH` constant, resolved relative to the manager home directory).

**Storage conventions:**
- DataValue entries use `{session}_{seq}` keys
- DataContext entries use `{session}_{seq}_context` keys
- Session data is deleted after successful completion, error handling, or stale-session cleanup
- The RocksDB directory is cleared (`remove_all`) when the module starts

**Location:** `/var/wazuh-manager/queue/inventory_sync/`

---

## Dependencies

### Router Dependency

The module subscribes to the Router and expects FlatBuffer messages on the `inventory-states` topic. Responses (`StartAck`, `EndAck`, `ReqRet`) are **not** sent back over the Router; they are written to the manager active-response datagram socket `queue/sockets/ar`, framed as `(msg_to_agent) [] N!s <agentId> <size> <module>_sync <flatbuffer>`, and delivered to the agent by `remoted`.

**Requirements:**
- Router must be active on the manager (inbound `inventory-states` topic)
- Agents must emit the synchronization protocol
- The active-response socket (`queue/sockets/ar`) must be available for `StartAck`, `EndAck`, and `ReqRet` responses

### Indexer Dependency

All indexing, delete-by-query, search, and update-by-query operations are delegated to the Indexer Connector.

**Requirements:**
- Wazuh Indexer must be healthy and accessible
- SSL certificates must be configured correctly
- Indexer must accept bulk operations

**Verify indexer connection:**
```bash
curl --cacert /var/wazuh-manager/etc/certs/root-ca.pem \
     --cert /var/wazuh-manager/etc/certs/manager.pem \
     --key /var/wazuh-manager/etc/certs/manager-key.pem \
     https://127.0.0.1:9200/_cluster/health
```

### Vulnerability Scanner Interaction

No dedicated configuration flag enables or disables vulnerability processing.

**How it works:**
- Session Start message carries the `option` field (`Sync`, `VDFirst`, or `VDSync`)
- Inventory Sync checks whether the Vulnerability Scanner is initialized
- Module either triggers or skips the downstream scan based on initialization state

---

## Performance Considerations

### Session Limit Sizing

**Small deployments (<500 agents):**
```ini
wazuh_modules.max_sessions=500
```

**Medium deployments (500-2000 agents):**
```ini
wazuh_modules.max_sessions=1000
```

**Large deployments (2000+ agents):**
```ini
wazuh_modules.max_sessions=5000
```

### Queue Sizing

The `inventory_sync_queue_size` parameter controls memory usage and message buffering:

- **Small (<500 agents):** 5000-10000 messages
- **Medium (500-2000 agents):** 10000-25000 messages
- **Large (2000+ agents):** 25000-100000 messages

### DataValue Quota

Balance between allowing large inventory payloads and preventing memory exhaustion:

- **Conservative:** 250000 (default; supports ~250 concurrent medium-sized inventories)
- **Balanced:** 500000
- **Aggressive:** 2000000 (supports many large inventories)

### Indexer Bulk Settings

**Low latency (fast indexing):**
```ini
wazuh_modules.inventory_sync_indexer_bulk_size_bytes=1048576
wazuh_modules.inventory_sync_indexer_flush_interval=5
```

**High throughput (better performance):**
```ini
wazuh_modules.inventory_sync_indexer_bulk_size_bytes=20971520
wazuh_modules.inventory_sync_indexer_flush_interval=30
```

**Balanced (default):**
```ini
wazuh_modules.inventory_sync_indexer_bulk_size_bytes=10485760
wazuh_modules.inventory_sync_indexer_flush_interval=20
```

---

## Monitoring

### Check Module Status

Verify Inventory Sync is running:

```bash
# Check manager status
systemctl status wazuh-manager

# Verify module loaded
grep "inventory-sync" /var/wazuh-manager/logs/wazuh-manager.log
```

### View Session Activity

Monitor active sessions and message processing:

```bash
# View inventory sync logs
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep inventory-sync

# Check for session activity
grep "session.*start\|session.*end" /var/wazuh-manager/logs/wazuh-manager.log
```

### Monitor Queue Status

Check for queue overflow warnings:

```bash
# Monitor queue warnings
grep -i "queue.*full\|dropped" /var/wazuh-manager/logs/wazuh-manager.log | \
  grep inventory-sync
```

### Check Quota Usage

Monitor DataValue quota rejections:

```bash
# View quota rejection events
grep "quota.*exceeded\|Status_Offline" /var/wazuh-manager/logs/wazuh-manager.log | \
  grep inventory-sync
```

### Indexer Performance

Monitor indexer bulk operations:

```bash
# Check indexer flush operations
grep "indexer.*flush\|bulk" /var/wazuh-manager/logs/wazuh-manager.log | \
  grep inventory-sync
```

### RocksDB Storage

Check session storage usage:

```bash
# Check RocksDB directory size
du -sh /var/wazuh-manager/queue/inventory_sync/

# List active session data
ls -lh /var/wazuh-manager/queue/inventory_sync/
```

---

## Troubleshooting

### Module Won't Start

**Cause:** Missing cluster name configuration

**Solution:**
1. Verify cluster configuration exists:
   ```bash
   grep -A5 "<cluster>" /var/wazuh-manager/etc/wazuh-manager.conf
   ```
2. Ensure `<name>` is set in cluster configuration
3. Restart manager:
   ```bash
   systemctl restart wazuh-manager
   ```

### Sessions Being Rejected

**Cause:** Session limit reached

**Solution:**
1. Increase session limit:
   ```ini
   wazuh_modules.max_sessions=5000
   ```
2. Restart manager to apply changes

**Cause:** DataValue quota exhausted

**Solution:**
1. Increase quota:
   ```ini
   wazuh_modules.inventory_sync_data_value_quota=1000000
   ```
2. Review agent inventory sizes
3. Restart manager to apply changes

### Messages Being Dropped

**Cause:** Input queue full

**Solution:**
1. Increase queue size:
   ```ini
   wazuh_modules.inventory_sync_queue_size=50000
   ```
2. Check for performance bottlenecks
3. Restart manager to apply changes

### Slow Indexing

**Cause:** Bulk size too small or flush interval too long

**Solution:**
1. Optimize bulk settings:
   ```ini
   wazuh_modules.inventory_sync_indexer_bulk_size_bytes=20971520
   wazuh_modules.inventory_sync_indexer_flush_interval=10
   ```
2. Verify indexer health
3. Restart manager to apply changes

### Indexer Connection Failures

**Cause:** Indexer unavailable or SSL certificate issues

**Solution:**
1. Verify indexer is healthy:
   ```bash
   curl --cacert /var/wazuh-manager/etc/certs/root-ca.pem \
        --cert /var/wazuh-manager/etc/certs/manager.pem \
        --key /var/wazuh-manager/etc/certs/manager-key.pem \
        https://127.0.0.1:9200/_cluster/health
   ```
2. Check SSL certificate paths in configuration
3. Verify network connectivity to indexer
4. Review logs for specific errors:
   ```bash
   grep -i "indexer.*error\|ssl.*error" /var/wazuh-manager/logs/wazuh-manager.log
   ```

### Stale Sessions Not Cleaning Up

**Cause:** Sessions inactive for >20 minutes

**Solution:**
- Cleanup happens automatically every 10 minutes
- Check logs for cleanup sweep activity:
  ```bash
  grep "cleanup\|stale" /var/wazuh-manager/logs/wazuh-manager.log | grep inventory-sync
  ```
- If sessions persist, check RocksDB storage and consider manual cleanup:
  ```bash
  systemctl stop wazuh-manager
  rm -rf /var/wazuh-manager/queue/inventory_sync/*
  systemctl start wazuh-manager
  ```

### High Memory Usage

**Cause:** Too many concurrent sessions or large DataValue quota

**Solution:**
1. Reduce session limit:
   ```ini
   wazuh_modules.max_sessions=500
   ```
2. Reduce DataValue quota:
   ```ini
   wazuh_modules.inventory_sync_data_value_quota=250000
   ```
3. Reduce queue size:
   ```ini
   wazuh_modules.inventory_sync_queue_size=5000
   ```
4. Restart manager to apply changes

---

## See Also

- [Inventory Sync Module](index.html) - Module overview and architecture
- [Router Configuration](../router/configuration.md) - Message bus configuration
- [Indexer Connector Configuration](../indexer-connector/configuration.md) - Indexer integration
- [Vulnerability Scanner Configuration](../vulnerability-scanner/configuration.md) - Vulnerability scanning integration
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
