# Engine Configuration Reference

Complete configuration reference for the Wazuh Engine (analysisd) module.

The Wazuh Engine is the core event processing and detection module that handles log analysis, rule matching, decoder execution, and alert generation. It is configured primarily through internal options, with no dedicated XML or YAML configuration section of its own — though a subset of keys, such as indexer connection settings, are populated from the manager's central configuration rather than set directly as internal options.

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

The Engine is configured primarily through internal options; there is no dedicated XML block or YAML configuration file for this module. However, a subset of keys — such as the indexer host, credentials, and SSL settings — are populated from the manager's central configuration rather than set directly as internal options (see [Architecture - Configuration](architecture.md#configuration)). All other settings are tuned via the internal options file.

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

- **`analysisd.indexer_bulk_max_bytes`** - Maximum byte size of the bulk payload accumulated before a `_bulk` request is dispatched (bytes, not event count; allowed range 64KB-100MB)
- **`analysisd.indexer_flush_interval`** - Periodic flush interval (seconds)
- **`analysisd.indexer_max_retry_delay`** - Maximum exponential-backoff retry delay in seconds (default: 15, range: 1-3600). See [Indexer Connector - Retry and backoff behavior](../indexer_connector/README.md#retry-and-backoff-behavior) for how the delay scales between retries.
- **`analysisd.indexer_request_timeout`** - Upper bound in seconds for one data request against the indexer (default: 60, range: 0-3600; 0 disables the bound). Catches a host that accepted the connection and then never answers; a timed-out bulk request is retried with backoff, not discarded.
- **`analysisd.indexer_monitoring_interval`** - Polling period in seconds of the indexer health monitor that marks each host as available or unavailable (default: 10, range: 1-3600)

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
analysisd.event_queue_size=131072
analysisd.event_queue_eps=0

# Indexer connector
analysisd.indexer_bulk_max_bytes=8388608
analysisd.indexer_flush_interval=20

# Synchronization
analysisd.remote_conf_sync_interval=120
analysisd.cm_sync_interval=120

# Database updates
analysisd.ioc_sync_interval=360
analysisd.geo_sync_interval=360
```

### High-Throughput Configuration

Optimized for large deployments with high event rates:

```ini
# Larger event queue than the default
analysisd.event_queue_size=262144
analysisd.event_queue_eps=0

# Larger bulk payload for better indexer throughput, flushed more often
analysisd.indexer_bulk_max_bytes=33554432
analysisd.indexer_flush_interval=5

# More frequent synchronization than the default
analysisd.remote_conf_sync_interval=60
analysisd.cm_sync_interval=60
```

### Low-Resource Configuration

Optimized for resource-constrained environments:

```ini
# Smaller event queue, explicit rate cap to protect a constrained host
analysisd.event_queue_size=8192
analysisd.event_queue_eps=100

# Smaller bulk payload, flushed less often
analysisd.indexer_bulk_max_bytes=1048576
analysisd.indexer_flush_interval=60

# Less frequent synchronization than the default
analysisd.remote_conf_sync_interval=600
analysisd.cm_sync_interval=7200
```

### Development Configuration

Settings for testing and development:

```ini
# Moderate queue size, smaller than the default
analysisd.event_queue_size=16384
analysisd.event_queue_eps=500

# Minimum allowed bulk size for immediate, per-event feedback
analysisd.indexer_bulk_max_bytes=65536
analysisd.indexer_flush_interval=1

# Frequent sync for testing (shorter than the default)
analysisd.remote_conf_sync_interval=60
analysisd.cm_sync_interval=60

# Frequent database updates (shorter than the default)
analysisd.ioc_sync_interval=60
analysisd.geo_sync_interval=60
```

---

## API Configuration

The engine exposes an internal HTTP API over a **Unix domain socket** (default: `/var/wazuh-manager/queue/sockets/engine-api-http.sock`, internal option `analysisd.server_api_socket`) — not a TCP port. Requests and responses are plain JSON, validated against protobuf schemas on both ends. It is used for content/policy management, testing, routing, and metrics.

**Complete API documentation:** See [API Reference](api-reference.md)

### Key API Endpoints

- **Content Management** - Create, update, and validate namespaces, policies, and resources (decoders, rules, filters, outputs, integrations) under `/content/*` and `/_internal/content/*`
- **Schema Validation** - Validate a policy or resource before deployment (`/content/validate/policy`, `/content/validate/resource`)
- **Metrics** - Query engine performance metrics and statistics (`/metrics/get`, `/metrics/list`, `/metrics/dump`)
- **Router/Tester** - Manage routes and run test sessions against policies (`/_internal/router/*`, `/_internal/tester/*`)

### API Usage Example

Because the API is served over a Unix domain socket rather than a TCP port, it cannot be reached with a bare `curl -X GET https://...` call. Use `curl`'s `--unix-socket` option, or the `engine-suite` CLI tools (`engine-public`, `engine-private`, `engine-router`, `engine-test`, `engine-event-dumper`) that wrap these calls — see [Internal Tools](internal-tools.md).

Dump all current metrics:

```bash
curl -s --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock \
  -X POST http://localhost/metrics/dump \
  -H "Content-Type: application/json" -d '{}'
```

Validate a policy configuration:

```bash
curl -s --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock \
  -X POST http://localhost/content/validate/policy \
  -H "Content-Type: application/json" \
  -d @policy.json
```

or, using the `engine-suite` CLI wrapper instead of a raw socket call:

```bash
engine-public cm policy-validate < policy.json
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
analysisd.event_queue_size=32768
analysisd.event_queue_eps=500
```

**Large deployments (1000+ agents):** the built-in default already targets this profile
```ini
analysisd.event_queue_size=131072
analysisd.event_queue_eps=0
```

### Indexer Bulk Sizing

Balance between indexing latency and throughput:

- **Low latency (fast alerts):** Smaller bulk size, shorter flush interval
- **High throughput:** Larger bulk size, longer flush interval
- **Balanced:** Default settings (8 MB bulk size, 20s flush interval)

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

# Check engine status via the CLI wrapper (calls GET /status)
engine-public status get

# Equivalent raw call over the Unix domain socket
curl -s --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock http://localhost/status
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

Query engine performance via the API (Unix domain socket, `--unix-socket`):

```bash
# List all registered metric names
curl -s --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock \
  -X POST http://localhost/metrics/list \
  -H "Content-Type: application/json" -d '{}'

# Get a single metric's value, e.g. the global event-processing counter
curl -s --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock \
  -X POST http://localhost/metrics/get \
  -H "Content-Type: application/json" -d '{"instrumentName": "router.events.processed"}'

# Dump every metric (global + per-space) in one call
curl -s --unix-socket /var/wazuh-manager/queue/sockets/engine-api-http.sock \
  -X POST http://localhost/metrics/dump \
  -H "Content-Type: application/json" -d '{}'
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
1. Increase queue size (default is `131072`):
   ```ini
   analysisd.event_queue_size=262144
   ```
2. Raise or remove the EPS limit (`0` means unlimited, which is the default):
   ```ini
   analysisd.event_queue_eps=0
   ```
3. Restart manager to apply changes:
   ```bash
   systemctl restart wazuh-manager
   ```

### Slow Alert Generation

**Cause:** Indexer bulk buffer not flushing efficiently

**Solution:**
1. Reduce bulk size for faster flushing (default is `8388608`, i.e. 8MB):
   ```ini
   analysisd.indexer_bulk_max_bytes=1048576
   ```
2. Reduce flush interval (default is `20`):
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
