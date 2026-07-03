# Remoted Configuration Reference

Complete configuration reference for the Remoted module.

The remoted module is responsible for managing secure communication between Wazuh agents and the manager. It handles agent connections, authentication, message routing, and event enrichment. This is a manager-only module.

For module overview and architecture, see [Remoted Module](index.html).

---

## Main Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<remote>`

**Module:** Manager-only

**Internal Options:** `remoted.*`

The remoted module configuration controls how the manager listens for and processes agent communications.

### port

Listening port for agent connections.

- **Default value:** `1514`
- **Allowed values:** Integer from `1` to `65535`
- **Note:** Standard port for Wazuh agent-manager communication

### protocol

Communication protocol(s) to accept from agents.

- **Default value:** `tcp`
- **Allowed values:** `tcp`, `udp`, or `tcp,udp`
- **Note:** TCP is recommended for reliable delivery; UDP may be used for low-latency environments

### queue_size

Message queue size for incoming agent messages.

- **Default value:** `131072`
- **Allowed values:** Positive integer
- **Note:** Values greater than `262144` will generate a warning; adjust based on agent count and event rate

### allow_higher_versions

Accept connections from agents running a Wazuh version higher than the manager.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** Enable when upgrading agents before the manager

---

## Internal Options

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`

**Internal Options prefix:** `remoted.*`

Internal options provide advanced tuning for performance, threading, memory management, and monitoring.

### remoted.debug

Debug logging level for remoted module.

- **Default value:** `0`
- **Allowed values:** `0` (disabled), `1` (basic), `2` (verbose)
- **Note:** Use `debug2` for troubleshooting; generates significant log volume

### remoted.receive_chunk

Network receive buffer size in bytes.

- **Default value:** `4096`
- **Allowed values:** Positive integer
- **Note:** Larger values may improve throughput on high-bandwidth networks

### remoted.send_timeout_to_retry

Timeout in seconds before retrying a failed send operation.

- **Default value:** `5`
- **Allowed values:** Positive integer
- **Note:** Lower values increase retry frequency; higher values reduce network overhead

### remoted.worker_pool

Number of worker threads for processing agent messages.

- **Default value:** `4`
- **Allowed values:** Positive integer
- **Note:** Increase for high-throughput environments (e.g., `8` for >50K events/sec)

### remoted.sender_pool

Number of sender threads for forwarding events to the engine.

- **Default value:** `8`
- **Allowed values:** Positive integer
- **Note:** Increase for high-throughput environments (e.g., `16` for >50K events/sec)

### remoted.control_msg_queue_size

Queue size for agent keep-alive and control messages.

- **Default value:** `16384`
- **Allowed values:** Positive integer
- **Note:** Increase for large agent counts (e.g., `32768` for >10K agents)

### remoted.batch_events_capacity

Queue capacity for batching events before forwarding to the engine.

- **Default value:** `131072`
- **Allowed values:** Positive integer
- **Note:** Increase for high event rates (e.g., `262144` for >50K events/sec)

### remoted.queue_max_bytes

Maximum bytes held in the input message queue (messages received from agents).

- **Default value:** `67108864` (64 MiB)
- **Allowed values:** `0` (unlimited) or integer from `1024` upward
- **Note:** Caps memory usage; events exceeding the limit are dropped; set to `0` to disable byte limiting

### remoted.batch_events_max_bytes

Maximum bytes held in the events queue (events forwarded to the engine).

- **Default value:** `33554432` (32 MiB)
- **Allowed values:** `0` (unlimited) or integer from `1024` upward
- **Note:** Caps memory usage; events exceeding the limit are dropped; set to `0` to disable byte limiting

### remoted.enrich_cache_expire_time

Agent metadata cache expiration time in seconds.

- **Default value:** `300` (5 minutes)
- **Allowed values:** Integer from `60` to `86400`
- **Note:** Entries older than this threshold are cleaned up periodically; adjust based on agent stability (ephemeral: `300`, stable: `600-1800`)

### remoted.keyupdate_interval

Interval in seconds for reloading agent key files.

- **Default value:** `60`
- **Allowed values:** Positive integer
- **Note:** Lower values detect new agents faster but increase I/O overhead

### remoted.rlimit_nofile

Maximum number of open file descriptors for the remoted process.

- **Default value:** System default
- **Allowed values:** Positive integer
- **Note:** Increase for large agent counts (e.g., `131072` for >10K agents)

### remoted.state_interval

Interval in seconds for writing statistics to the state file.

- **Default value:** `5`
- **Allowed values:** `0` (disabled) or positive integer
- **Note:** Set to `0` to disable statistics; lower values provide more frequent updates

---

## Configuration Examples

### Default Configuration

Standard settings for most deployments:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
    <agents>
      <allow_higher_versions>no</allow_higher_versions>
    </agents>
  </remote>
</wazuh_config>
```

### UDP and TCP Support

Accept agent connections via both TCP and UDP protocols:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp,udp</protocol>
    <queue_size>131072</queue_size>
  </remote>
</wazuh_config>
```

### Large Agent Deployments (>10K agents)

Optimized for high agent counts:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>262144</queue_size>
  </remote>
</wazuh_config>
```

Internal options (`/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`):

```conf
remoted.control_msg_queue_size=32768
remoted.keyupdate_interval=30
remoted.rlimit_nofile=131072
```

### High Throughput (>50K events/sec)

Optimized for high event rates:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>262144</queue_size>
  </remote>
</wazuh_config>
```

Internal options:

```conf
remoted.control_msg_queue_size=32768
remoted.batch_events_capacity=262144
remoted.worker_pool=8
remoted.sender_pool=16
```

### Low Memory Environments

Reduced memory footprint for resource-constrained systems:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>65536</queue_size>
  </remote>
</wazuh_config>
```

Internal options:

```conf
remoted.control_msg_queue_size=4096
remoted.batch_events_capacity=32768
remoted.worker_pool=2
remoted.sender_pool=4
```

### Ephemeral Agents (Short-Lived)

Optimized for ephemeral or containerized agents with frequent restarts:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
</wazuh_config>
```

Internal options:

```conf
# Short cache expiration for ephemeral agents
remoted.enrich_cache_expire_time=300

# Standard queue sizes
remoted.control_msg_queue_size=16384
remoted.batch_events_capacity=131072
```

### Stable Long-Running Agents

Optimized for stable, long-running agents with infrequent restarts:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
</wazuh_config>
```

Internal options:

```conf
# Longer cache expiration for stable agents
remoted.enrich_cache_expire_time=1800

# Standard queue sizes
remoted.control_msg_queue_size=16384
remoted.batch_events_capacity=131072
```

### Allow Higher Agent Versions

Allow agents with newer Wazuh versions to connect during rolling upgrades:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
    <agents>
      <allow_higher_versions>yes</allow_higher_versions>
    </agents>
  </remote>
</wazuh_config>
```

### Memory-Capped Queues

Limit memory consumption with byte caps regardless of event count:

```xml
<wazuh_config>
  <remote>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
</wazuh_config>
```

Internal options:

```conf
# Cap input queue at 128 MiB
remoted.queue_max_bytes=134217728

# Cap events queue at 64 MiB
remoted.batch_events_max_bytes=67108864
```

---

## Queue Byte Limits

The byte limit options (`remoted.queue_max_bytes` and `remoted.batch_events_max_bytes`) cap the total memory used by queues regardless of event count. This is useful when agents send large events that would otherwise cause unbounded memory growth even at normal event rates.

### Behavior When Limits Are Reached

- Events that individually exceed the limit are dropped immediately
- Events that would push the total over the limit are dropped until space is freed
- Dropped events increment the same discard counter as a full queue (`discarded_count` in the state file)
- A warning is logged at most once every 5 seconds to avoid log flooding

### Guidelines

- The byte limit and event-count limit (`batch_events_capacity`) are independent. An event is dropped if either limit is reached.
- Values between `1` and `1023` bytes are rejected at startup as they are almost certainly a configuration error.
- Set to `0` to revert to count-only limiting.

### Sizing Examples

**Small deployments (<1K agents):**
```conf
remoted.control_msg_queue_size=4096
remoted.batch_events_capacity=32768
```

**Medium deployments (1K-10K agents):**
```conf
remoted.control_msg_queue_size=16384
remoted.batch_events_capacity=131072
```

**Large deployments (>10K agents):**
```conf
remoted.control_msg_queue_size=32768
remoted.batch_events_capacity=262144
```

---

## Stateless Metadata Cache

The stateless metadata cache stores agent metadata extracted from keep-alive messages to enrich stateless events.

### Cache Expiration Guidelines

**Ephemeral/short-lived agents:**
```conf
remoted.enrich_cache_expire_time=300  # 5 minutes (default)
```

**Stable agents with occasional restarts:**
```conf
remoted.enrich_cache_expire_time=600  # 10 minutes
```

**Long-running stable agents:**
```conf
remoted.enrich_cache_expire_time=1800  # 30 minutes
```

The cleanup process runs every 60 seconds and removes entries that haven't received a keep-alive in the configured time period.

### Hash Table Tuning

Metadata cache bucket count (requires recompile of `src/remoted/agent_metadata_db.c`):

**<10K agents:**
- Default: 2048 buckets

**10K-50K agents:**
- Recommended: 4096 buckets

**>50K agents:**
- Recommended: 8192 buckets

---

## Monitoring

### Enable Statistics

Enable statistics in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`:

```conf
remoted.state_interval=5
```

View statistics:
```bash
cat /var/wazuh-manager/var/run/wazuh-manager-remoted.state
```

### Enable Debug Logging

Enable verbose logging in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`:

```conf
remoted.debug=2
```

View logs:
```bash
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep remoted
```

### Check Queue Status

Monitor queue depths and dropped events:
```bash
# View state file
cat /var/wazuh-manager/var/run/wazuh-manager-remoted.state

# Watch for discarded events
grep "discarded_count" /var/wazuh-manager/var/run/wazuh-manager-remoted.state
```

---

## See Also

- [Remoted Module](index.html) - Module overview and architecture
- [Stateless Metadata](stateless-metadata.md) - Agent metadata caching system
- [Event Protocol](event-protocol.md) - Agent-manager communication protocol
- [Architecture](architecture.md) - Module design and implementation
- [Quick Reference](quick-reference.md) - Command reference and troubleshooting
