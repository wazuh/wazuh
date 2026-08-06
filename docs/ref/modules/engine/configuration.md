# Engine Configuration Reference

Complete configuration reference for the Wazuh Engine (analysisd) module.

The Wazuh Engine is the core event processing and detection module that handles log analysis, rule matching, decoder execution, and alert generation. It is configured exclusively through internal options, with no XML or YAML configuration sections.

- **Daemon:** `wazuh-manager-analysisd`
- **Module:** Manager-only
- **Configuration method:** Internal options only

For module overview, architecture, and implementation details, see [Engine Module](index.html).

---

## Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`

**XML Section:** None

**YAML Section:** None

**Internal Options:** `analysisd.*`

The Engine is configured exclusively through internal options. There is no dedicated XML block or YAML configuration file for this module. All settings are tuned via the internal options file.

---

## Internal Options Reference

All engine settings are configured through internal options prefixed with `analysisd.*` in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`.

**Complete internal options documentation:** See [Internal options reference](index.html#internal-options-reference) in the Engine Module documentation.

### Key Configuration Areas

The engine provides internal options for:

#### Process Privileges

The engine daemon is launched as `root` and drops privileges at startup when
running as part of wazuh-manager (it keeps the launcher's user and group when
running standalone, e.g. inside wazuh-indexer). The target user and group are
hardcoded to `wazuh-manager:wazuh-manager`; only the drop itself is
configurable:

- **`analysisd.drop_privileges`** - Switch to the `wazuh-manager` user and
  group at startup (default: `true`). Set to `false` to keep running as the
  launching user (debugging only). Has no effect in standalone mode.

If the user or group change fails, the daemon logs the error and exits at
startup.

##### Switching back to `true` after running as `root`

While `analysisd.drop_privileges` is `false` the daemon keeps running as
`root`, so every file and directory it creates under `/var/wazuh-manager`
belongs to `root:root` and is not group-writable. Setting the option back to
`true` (or removing it, since `true` is the default) makes the daemon start as
`wazuh-manager`, which can no longer write that content, and startup fails
with a permission error naming the offending path. For example:

```
Cannot create directory in base path: /var/wazuh-manager/data/ruleset: Permission denied
Failed to create KVDB root directory: Permission denied
```

The ownership must be fixed manually before restarting the daemon. The paths
the engine creates or writes at runtime are:

| Path | Contents |
|------|----------|
| `/var/wazuh-manager/data/store` | Engine store documents |
| `/var/wazuh-manager/data/ruleset` | Content Manager ruleset (write-tested at startup) |
| `/var/wazuh-manager/data/kvdb-ioc` | IOC KVDB (RocksDB files, must be owner-writable) |
| `/var/wazuh-manager/data/mmdb` | Downloaded geolocation databases |
| `/var/wazuh-manager/data/tzdb` | Time-zone database |
| `/var/wazuh-manager/logs/<YYYY>/<MMM>/` | Rotated alert and archive files |
| `/var/wazuh-manager/var/run` | PID file |

With the daemon stopped, restore the ownership of the affected paths and start
it again:

```bash
chown -R wazuh-manager:wazuh-manager \
  /var/wazuh-manager/data \
  /var/wazuh-manager/logs \
  /var/wazuh-manager/var/run
```

The reverse transition (`true` → `false`) needs no fix, since `root` can write
files owned by `wazuh-manager`. To avoid the problem altogether, restore the
ownership right after every debugging session run with
`analysisd.drop_privileges=false`.

#### Event Queue Management

Control event queue sizing and processing rate limiting:

- **`analysisd.event_queue_size`** - Maximum events in processing queue
- **`analysisd.event_queue_eps`** - Events per second rate limiting

#### Indexer Connector Settings

Configure bulk indexing and flush behavior:

- **`analysisd.indexer_bulk_size_events`** - Maximum documents per bulk request (event count, not bytes)
- **`analysisd.indexer_flush_interval`** - Periodic flush interval (seconds)
- **`analysisd.indexer_max_retry_delay`** - Maximum exponential-backoff retry delay in seconds (default: 15, range: 1-3600). See [Indexer Connector - Retry and backoff behavior](../indexer_connector/README.md#retry-and-backoff-behavior) for how the delay scales between retries.

#### Synchronization Intervals

Control remote configuration and content synchronization:

- **`analysisd.remote_conf_sync_interval`** - Remote configuration sync interval
- **`analysisd.cm_sync_interval`** - Content Manager sync interval

#### Database Synchronization

Configure database update frequencies:

- **`analysisd.ioc_sync_interval`** - Indicator of Compromise database sync interval
- **`analysisd.geo_sync_interval`** - GeoIP database update interval

For complete details, default values, allowed ranges, and additional internal options, see the [Internal options reference](index.html#internal-options-reference) section in the Engine Module documentation.

---

## Configuration Examples

### Default Internal Options

Standard engine configuration for most deployments:

```ini
# Event queue
analysisd.event_queue_size=16384
analysisd.event_queue_eps=200

# Indexer connector
analysisd.indexer_bulk_size_events=50000
analysisd.indexer_flush_interval=10

# Synchronization
analysisd.remote_conf_sync_interval=300
analysisd.cm_sync_interval=3600

# Database updates
analysisd.ioc_sync_interval=86400
analysisd.geo_sync_interval=86400
```

### High-Throughput Configuration

Optimized for large deployments with high event rates:

```ini
# Larger event queue
analysisd.event_queue_size=32768
analysisd.event_queue_eps=1000

# Larger bulk size for better indexer performance
analysisd.indexer_bulk_size_events=100000
analysisd.indexer_flush_interval=5

# More frequent synchronization
analysisd.remote_conf_sync_interval=120
analysisd.cm_sync_interval=1800
```

### Low-Resource Configuration

Optimized for resource-constrained environments:

```ini
# Smaller event queue
analysisd.event_queue_size=8192
analysisd.event_queue_eps=100

# Smaller bulk size
analysisd.indexer_bulk_size_events=10000
analysisd.indexer_flush_interval=20

# Less frequent synchronization
analysisd.remote_conf_sync_interval=600
analysisd.cm_sync_interval=7200
```

### Development Configuration

Settings for testing and development:

```ini
# Moderate queue size
analysisd.event_queue_size=16384
analysisd.event_queue_eps=500

# Fast indexing for quick feedback
analysisd.indexer_bulk_size_events=5000
analysisd.indexer_flush_interval=1

# Frequent sync for testing
analysisd.remote_conf_sync_interval=60
analysisd.cm_sync_interval=300

# Frequent database updates
analysisd.ioc_sync_interval=3600
analysisd.geo_sync_interval=3600
```

---

## API Configuration

The engine exposes API endpoints for policy and asset management under the `/engine` endpoint.

**Complete API documentation:** See [API Reference](api-reference.md)

### Key API Endpoints

- **Policy Management** - Create, update, and manage detection policies
- **Asset Management** - Manage decoders, rules, filters, and outputs
- **Schema Validation** - Validate configurations before deployment
- **Metrics** - Query engine performance metrics and statistics

### API Usage Example

Query engine metrics:

```bash
curl -k -X GET "https://localhost:55000/engine/metrics" \
  -H "Authorization: Bearer $TOKEN"
```

Validate policy configuration:

```bash
curl -k -X POST "https://localhost:55000/engine/validate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @policy.json
```

---

## Performance Considerations

### Event Queue Sizing

**Small deployments (<100 agents):**
```ini
analysisd.event_queue_size=8192
analysisd.event_queue_eps=100
```

**Medium deployments (100-1000 agents):**
```ini
analysisd.event_queue_size=16384
analysisd.event_queue_eps=200
```

**Large deployments (1000+ agents):**
```ini
analysisd.event_queue_size=32768
analysisd.event_queue_eps=1000
```

### Indexer Bulk Sizing

Balance between indexing latency and throughput:

- **Low latency (fast alerts):** Smaller bulk size, shorter flush interval
- **High throughput:** Larger bulk size, longer flush interval
- **Balanced:** Default settings (10 MB bulk size, 10s flush interval)

### Synchronization Frequency

Adjust based on update requirements:

- **Static environment:** Longer intervals reduce overhead
- **Dynamic environment:** Shorter intervals ensure current configuration
- **Production:** Balance between freshness and performance

---

## Monitoring

### Check Engine Status

Verify engine is running and processing events:

```bash
# Check analysisd process
ps aux | grep wazuh-manager-analysisd

# Check engine status via API
curl -k -X GET "https://localhost:55000/manager/status" \
  -H "Authorization: Bearer $TOKEN"
```

### View Engine Logs

Monitor engine activity and errors:

```bash
# Engine logs
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep analysisd

# Alert generation logs
tail -f /var/wazuh-manager/logs/alerts/alerts.log
```

### Performance Metrics

Query engine performance via API:

```bash
# Get engine metrics
curl -k -X GET "https://localhost:55000/engine/metrics" \
  -H "Authorization: Bearer $TOKEN"

# Get event processing rate
curl -k -X GET "https://localhost:55000/engine/stats/events" \
  -H "Authorization: Bearer $TOKEN"
```

### Queue Monitoring

Check event queue status:

```bash
# View queue statistics in logs
grep "event_queue" /var/wazuh-manager/logs/wazuh-manager.log

# Monitor for queue overflow warnings
grep -i "queue.*full\|dropped" /var/wazuh-manager/logs/wazuh-manager.log
```

---

## Troubleshooting

### Engine Won't Start

**Check internal options syntax:**
```bash
# Verify configuration file exists and is readable
ls -l /var/wazuh-manager/etc/wazuh-manager-internal-options.conf

# Check for syntax errors in logs
grep -i "error\|invalid" /var/wazuh-manager/logs/wazuh-manager.log | grep analysisd
```

**Verify process status:**
```bash
systemctl status wazuh-manager
ps aux | grep analysisd
```

### Events Being Dropped

**Cause:** Event queue full or EPS limit exceeded

**Solution:**
1. Increase queue size:
   ```ini
   analysisd.event_queue_size=32768
   ```
2. Increase EPS limit:
   ```ini
   analysisd.event_queue_eps=1000
   ```
3. Restart manager to apply changes:
   ```bash
   systemctl restart wazuh-manager
   ```

### Slow Alert Generation

**Cause:** Indexer bulk buffer not flushing efficiently

**Solution:**
1. Reduce bulk size for faster flushing:
   ```ini
   analysisd.indexer_bulk_size_events=10000
   ```
2. Reduce flush interval:
   ```ini
   analysisd.indexer_flush_interval=5
   ```

### High CPU Usage

**Cause:** Processing too many events or complex rules

**Solution:**
1. Enable rate limiting:
   ```ini
   analysisd.event_queue_eps=200
   ```
2. Review and optimize rules
3. Consider horizontal scaling with cluster

### Synchronization Failures

**Cause:** Network issues or service unavailable

**Solution:**
1. Check network connectivity to sync endpoints
2. Increase sync interval to reduce retry frequency:
   ```ini
   analysisd.remote_conf_sync_interval=600
   ```
3. Review logs for specific error messages:
   ```bash
   grep -i "sync.*fail\|sync.*error" /var/wazuh-manager/logs/wazuh-manager.log
   ```

---

## See Also

- [Engine Module](index.html) - Complete module documentation with internal options reference
- [API Reference](api-reference.md) - Engine API endpoints and usage
- [Architecture](architecture.md) - Engine design and implementation
- [Helper Functions Reference](ref-helper-functions.md) - Available helper functions
- [Parsers Reference](ref-parser.md) - Parser documentation
- [Outputs Reference](ref-output.md) - Output configuration
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
